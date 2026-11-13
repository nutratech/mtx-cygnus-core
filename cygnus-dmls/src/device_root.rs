//! Bridge MSC00FC device certificates and device roots into DMLS identities.
//!
//! The merge model takes identity resolution as an injected callback
//! ([`crate::merge::PrincipalOf`]); it knows nothing about certificates. This
//! module supplies that callback from room-level MSC00FC state:
//!
//! * [`DeviceRootRegistry`] holds the unambiguous `m.room.device_root` for each
//!   principal and the device certificates that were verified against a master
//!   key.
//! * [`DeviceRootRegistry::resolve`] is the strict resolver: the leaf's
//!   `signature_key` must be a certified device key, the leaf identity must
//!   name that device, and the certificate's self-signing key must equal the
//!   active root's self-signing key.
//! * [`DeviceRootRegistry::identity_of`] resolves identity without requiring
//!   the certificate to still be active. Merge planning needs this so it can
//!   *plan a removal* for a device that has been revoked or rotated.
//! * [`plan_with_device_roots`] turns inactive devices into Remove operations,
//!   refuses a stale base leaf when another branch has an active leaf for that
//!   device, and filters self-update requirements for removed devices.
//!
//! MLS leaf generation and `device_root.generation` remain separate: the former
//! is group-scoped and advances on a re-join, the latter is room identity state.

use std::collections::{BTreeMap, BTreeSet};

use cygnus_core::DeviceCertificate;

use crate::merge::{
    plan_merge, Branch, ExtremityId, LeafVerifier, MemberId, MergeError, MergePlan, PrincipalDevice,
};
use crate::tree::LeafNode;

fn uncertified(message: &'static str) -> MergeError {
    MergeError::UncertifiedDevice(message)
}

const INACTIVE: &str = "device certificate is revoked or stale for the active device_root";

/// The active, unambiguous MSC00FC device root for one principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRoot {
    /// The principal's user ID.
    pub principal: String,
    /// The user epoch height the root was published at.
    pub user_epoch_height: u64,
    /// The device-root generation.
    pub generation: u64,
    /// The self-signing key the root certifies.
    pub self_signing_key: [u8; 32],
}

/// One device key that was verified against a master key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedDevice {
    /// The principal's user ID.
    pub principal: String,
    /// The device ID.
    pub device_id: String,
    /// The device's Ed25519 key.
    pub device_key: [u8; 32],
    /// The self-signing key that certified the device.
    pub self_signing_key: [u8; 32],
}

/// Certified devices plus the active device roots for one room view.
#[derive(Debug, Clone, Default)]
pub struct DeviceRootRegistry {
    master_keys: BTreeMap<String, [u8; 32]>,
    roots: BTreeMap<String, DeviceRoot>,
    devices: BTreeMap<Vec<u8>, CertifiedDevice>,
    revoked: BTreeSet<Vec<u8>>,
}

impl DeviceRootRegistry {
    /// Create a registry from each principal's master key.
    #[must_use]
    pub fn new(master_keys: impl IntoIterator<Item = (String, [u8; 32])>) -> Self {
        Self {
            master_keys: master_keys.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Install a root already resolved from room state.
    ///
    /// The strict `+1` check is repeated here so a caller cannot silently
    /// install two unrelated roots at the same epoch height and generation.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError::UncertifiedDevice`] for a non-advancing,
    /// conflicting, or out-of-sequence root.
    pub fn install_root(&mut self, root: DeviceRoot) -> Result<(), MergeError> {
        match self.roots.get(&root.principal) {
            None => {
                if root.generation != 1 {
                    return Err(uncertified("first device_root must be generation 1"));
                }
            }
            Some(current) if root.user_epoch_height < current.user_epoch_height => {
                return Err(uncertified("device_root epoch height moved backwards"));
            }
            Some(current) if root.user_epoch_height == current.user_epoch_height => {
                if root.generation == current.generation {
                    if &root == current {
                        return Ok(());
                    }
                    return Err(uncertified(
                        "conflicting device_roots at the same epoch and generation",
                    ));
                }
                if root.generation != current.generation + 1 {
                    return Err(uncertified(
                        "device_root generation must advance by exactly one",
                    ));
                }
            }
            Some(_) => {
                if root.generation != 1 {
                    return Err(uncertified(
                        "first device_root at a new epoch height must be generation 1",
                    ));
                }
            }
        }
        self.roots.insert(root.principal.clone(), root);
        Ok(())
    }

    /// Verify the certificate chain and record the device key.
    ///
    /// Stale certificates are kept so merge planning can still recognise the
    /// member and propose a Remove; [`Self::is_active`] decides whether it may
    /// continue as a live leaf.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError::UncertifiedDevice`] if the principal has no master
    /// key or root, or the certificate does not verify.
    pub fn certify(
        &mut self,
        principal: &str,
        certificate: &rezzy_json::Value,
    ) -> Result<CertifiedDevice, MergeError> {
        let master_key = self
            .master_keys
            .get(principal)
            .ok_or_else(|| uncertified("no master key for principal"))?;
        let verified = DeviceCertificate::parse_and_verify(certificate, principal, master_key)
            .map_err(|_| uncertified("device certificate does not verify"))?;
        if !self.roots.contains_key(principal) {
            return Err(uncertified("principal has no device_root"));
        }
        let device = CertifiedDevice {
            principal: principal.to_owned(),
            device_id: verified.device_id,
            device_key: verified.device_key,
            self_signing_key: verified.self_signing_key,
        };
        self.devices
            .insert(device.device_key.to_vec(), device.clone());
        Ok(device)
    }

    /// Revoke a device key.
    pub fn revoke(&mut self, device_key: &[u8]) {
        self.revoked.insert(device_key.to_vec());
    }

    /// Whether this leaf's device key is certified by the active root.
    #[must_use]
    pub fn is_active(&self, leaf: &LeafNode) -> bool {
        let Some(device) = self.devices.get(&leaf.signature_key) else {
            return false;
        };
        if self.revoked.contains(&leaf.signature_key) {
            return false;
        }
        let Some(root) = self.roots.get(&device.principal) else {
            return false;
        };
        if device.self_signing_key != root.self_signing_key {
            return false;
        }
        identity_parts(leaf).is_ok_and(|(principal, device_id)| {
            device.principal == principal && device.device_id == device_id
        })
    }

    /// Resolve identity from a once-certified device, active or not.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError::UncertifiedDevice`] if the key was never
    /// certified, is certified for another device, or has no root.
    pub fn identity_of(&self, leaf: &LeafNode) -> Result<PrincipalDevice, MergeError> {
        let (principal, device_id) = identity_parts(leaf)?;
        let device = self
            .devices
            .get(&leaf.signature_key)
            .ok_or_else(|| uncertified("leaf signature key was never certified"))?;
        if device.principal != principal || device.device_id != device_id {
            return Err(uncertified(
                "leaf signature key is certified for a different device",
            ));
        }
        let root = self
            .roots
            .get(&principal)
            .ok_or_else(|| uncertified("principal has no device_root"))?;
        Ok(PrincipalDevice {
            principal: principal.into_bytes(),
            device_id,
            user_epoch_height: root.user_epoch_height,
            device_root_generation: root.generation,
        })
    }

    /// Strict resolver: the certificate must still chain to the active root.
    ///
    /// # Errors
    ///
    /// As [`Self::identity_of`], plus [`MergeError::UncertifiedDevice`] when the
    /// device is revoked or stale for the active root.
    pub fn resolve(&self, leaf: &LeafNode) -> Result<PrincipalDevice, MergeError> {
        let identity = self.identity_of(leaf)?;
        self.require_active(leaf)?;
        Ok(identity)
    }

    /// Require the leaf's device to be active.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError::UncertifiedDevice`] if it is not.
    pub fn require_active(&self, leaf: &LeafNode) -> Result<(), MergeError> {
        if self.is_active(leaf) {
            Ok(())
        } else {
            Err(uncertified(INACTIVE))
        }
    }

    /// Members whose current leaf cannot be certified by the active root.
    #[must_use]
    pub fn inactive_members(&self, branch: &Branch) -> Vec<MemberId> {
        branch
            .members
            .iter()
            .filter(|(_, record)| !self.is_active(&record.leaf))
            .map(|(member_id, _)| member_id.clone())
            .collect()
    }
}

/// Decode the model's `principal:device_id` identity convention.
fn identity_parts(leaf: &LeafNode) -> Result<(String, String), MergeError> {
    let text = std::str::from_utf8(&leaf.identity)
        .map_err(|_| uncertified("leaf identity is not principal:device"))?;
    text.rsplit_once(':')
        .map(|(principal, device)| (principal.to_owned(), device.to_owned()))
        .ok_or_else(|| uncertified("leaf identity is not principal:device"))
}

/// Plan a merge while reconciling active certificates and stale leaves.
///
/// A stale leaf cannot supersede an active leaf for the same device, whichever
/// branch wins base selection. A stale leaf is removed only when the resolved
/// member state is inactive; stale historical leaves do not evict a valid
/// re-certification from another branch.
///
/// `verify_leaf` is mandatory on this path: the device-root bridge never plans
/// without `LeafNode` signature checks.
///
/// # Errors
///
/// Returns a [`MergeError`] from [`plan_merge`], or
/// [`MergeError::UncertifiedDevice`] if a stale or revoked leaf would supersede
/// an active certificate for the same device.
pub fn plan_with_device_roots(
    requested: impl IntoIterator<Item = ExtremityId>,
    held: &BTreeMap<ExtremityId, Branch>,
    group_id: &[u8],
    registry: &DeviceRootRegistry,
    verify_leaf: LeafVerifier<'_>,
) -> Result<MergePlan, MergeError> {
    let requested: Vec<ExtremityId> = requested.into_iter().collect();
    let mut plan = plan_merge(
        requested.iter().copied(),
        held,
        group_id,
        &|leaf| registry.identity_of(leaf),
        Some(verify_leaf),
    )?;

    let branches: Vec<&Branch> = requested.iter().filter_map(|ext| held.get(ext)).collect();
    let active_anywhere: BTreeSet<&MemberId> = branches
        .iter()
        .flat_map(|branch| branch.members.iter())
        .filter(|(_, record)| registry.is_active(&record.leaf))
        .map(|(member_id, _)| member_id)
        .collect();

    for (member_id, record) in &plan.members {
        if !registry.is_active(&record.leaf) && active_anywhere.contains(member_id) {
            return Err(uncertified(
                "stale or revoked leaf supersedes an active certificate for the same device",
            ));
        }
    }

    // A self-update is only worth requiring when some branch holds an active,
    // newer leaf for the member; a stale or revoked candidate never justifies it.
    let has_active_newer = |member_id: &MemberId| {
        let Some(base) = plan.members.get(member_id) else {
            return false;
        };
        branches.iter().any(|branch| {
            branch.members.get(member_id).is_some_and(|record| {
                registry.is_active(&record.leaf) && record.leaf.generation > base.leaf.generation
            })
        })
    };
    plan.required_self_updates = plan
        .required_self_updates
        .iter()
        .filter(|member_id| has_active_newer(member_id))
        .cloned()
        .collect();

    let inactive: BTreeSet<MemberId> = plan
        .members
        .iter()
        .filter(|(_, record)| !registry.is_active(&record.leaf))
        .map(|(member_id, _)| member_id.clone())
        .collect();
    if inactive.is_empty() {
        return Ok(plan);
    }

    let base_members = &held
        .get(&plan.base)
        .ok_or(MergeError::Invalid("selected base is not held"))?
        .members;
    let mut removed: BTreeSet<MemberId> = plan.removes.iter().cloned().collect();
    removed.extend(
        inactive
            .iter()
            .filter(|member_id| base_members.contains_key(*member_id))
            .cloned(),
    );
    plan.members
        .retain(|member_id, _| !inactive.contains(member_id));
    plan.required_self_updates
        .retain(|member_id| !inactive.contains(member_id));
    plan.adds
        .retain(|(member_id, _)| !inactive.contains(member_id));
    plan.removes = removed.into_iter().collect();
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use ed25519_zebra::SigningKey;

    use super::*;
    use crate::merge::{LeafOrigin, LeafRecord};

    // A canonical user principal (`@` + base64url of a 32-byte digest).
    const PRINCIPAL: &str = "@BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    const GROUP: &[u8] = b"dmls-00fc-test";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from([seed; 32])
    }

    fn public(key: &SigningKey) -> [u8; 32] {
        <[u8; 32]>::from(key.verification_key())
    }

    fn root(generation: u64, self_signing: &SigningKey) -> DeviceRoot {
        DeviceRoot {
            principal: PRINCIPAL.to_owned(),
            user_epoch_height: 4,
            generation,
            self_signing_key: public(self_signing),
        }
    }

    fn certificate(
        master: &SigningKey,
        self_signing: &SigningKey,
        device: &SigningKey,
    ) -> rezzy_json::Value {
        DeviceCertificate::issue(PRINCIPAL, master, self_signing, "D1", device).unwrap()
    }

    fn leaf(hpke: &str, generation: u64, device: &SigningKey) -> LeafNode {
        let mut leaf = LeafNode::new(
            format!("{PRINCIPAL}:D1").into_bytes(),
            hpke.as_bytes().to_vec(),
        )
        .with_generation(generation)
        .with_group_id(GROUP.to_vec());
        leaf.signature_key = public(device).to_vec();
        leaf
    }

    fn accept(_: &LeafNode, _: Option<usize>, _: bool) -> bool {
        true
    }

    fn branch(byte: u8, members: Vec<(MemberId, LeafRecord)>) -> Branch {
        Branch::new(
            ExtremityId::new(1, [byte; 32]),
            vec![b'p'; 32],
            members.into_iter().collect(),
        )
    }

    fn plan(registry: &DeviceRootRegistry, branches: &[&Branch]) -> Result<MergePlan, MergeError> {
        let held = branches
            .iter()
            .map(|b| (b.extremity, (*b).clone()))
            .collect();
        plan_with_device_roots(
            branches.iter().map(|b| b.extremity),
            &held,
            GROUP,
            registry,
            &accept,
        )
    }

    #[test]
    fn resolver_requires_a_certified_key_and_removes_revoked_leaves() {
        let (master, self_signing, device) = (key(b'm'), key(b's'), key(b'd'));
        let mut registry = DeviceRootRegistry::new([(PRINCIPAL.to_owned(), public(&master))]);
        registry.install_root(root(1, &self_signing)).unwrap();
        registry
            .certify(PRINCIPAL, &certificate(&master, &self_signing, &device))
            .unwrap();

        let good = leaf("hpke-public-key", 0, &device);
        let resolved = registry.resolve(&good).unwrap();
        assert_eq!(resolved.principal, PRINCIPAL.as_bytes());
        assert_eq!(resolved.device_id, "D1");

        let mut wrong = good.clone();
        wrong.signature_key = vec![b'x'; 32];
        assert!(matches!(
            registry.resolve(&wrong),
            Err(MergeError::UncertifiedDevice(_))
        ));

        let member = resolved.member_id();
        let held = branch(b'r', vec![(member.clone(), LeafRecord::new(good.clone()))]);
        registry.install_root(root(2, &key(b'n'))).unwrap();
        assert!(!registry.is_active(&good));
        let result = plan(&registry, &[&held]).unwrap();
        assert_eq!(result.removes, vec![member.clone()]);
        assert!(!result.members.contains_key(&member));
    }

    #[test]
    fn install_root_enforces_strict_sequencing() {
        let ss = key(b's');
        let mut registry = DeviceRootRegistry::default();
        assert!(registry.install_root(root(2, &ss)).is_err());
        registry.install_root(root(1, &ss)).unwrap();
        registry.install_root(root(1, &ss)).unwrap();
        assert!(registry.install_root(root(1, &key(b'x'))).is_err());
        assert!(registry.install_root(root(3, &ss)).is_err());
        registry.install_root(root(2, &ss)).unwrap();
        let mut earlier = root(1, &ss);
        earlier.user_epoch_height = 3;
        assert!(registry.install_root(earlier).is_err());
        let mut next_epoch = root(2, &ss);
        next_epoch.user_epoch_height = 5;
        assert!(registry.install_root(next_epoch).is_err());
        next_epoch = root(1, &ss);
        next_epoch.user_epoch_height = 5;
        registry.install_root(next_epoch).unwrap();
    }

    #[test]
    fn rotation_rejects_stale_leaves_and_orders_candidates_by_activity() {
        let master = key(b'm');
        let (old_ss, old_dev) = (key(b's'), key(b'd'));
        let (new_ss, new_dev) = (key(b'R'), key(b'E'));
        let mut registry = DeviceRootRegistry::new([(PRINCIPAL.to_owned(), public(&master))]);
        registry.install_root(root(1, &old_ss)).unwrap();
        registry
            .certify(PRINCIPAL, &certificate(&master, &old_ss, &old_dev))
            .unwrap();
        registry.install_root(root(2, &new_ss)).unwrap();
        registry
            .certify(PRINCIPAL, &certificate(&master, &new_ss, &new_dev))
            .unwrap();

        let stale_leaf = leaf("hpke-old", 2, &old_dev);
        let active_leaf = leaf("hpke-new", 1, &new_dev);
        assert!(!registry.is_active(&stale_leaf));
        assert!(registry.is_active(&active_leaf));
        assert!(registry.resolve(&stale_leaf).is_err());
        let member = registry.resolve(&active_leaf).unwrap().member_id();

        let stale_base_leaf = leaf("hpke-old-base", 1, &old_dev);
        let active_update_leaf = leaf("hpke-new-update", 2, &new_dev);

        // An inactive base leaf cannot be replaced by another branch's active leaf.
        let stale_base = branch(
            b'a',
            vec![(member.clone(), LeafRecord::new(stale_base_leaf.clone()))],
        );
        let active_update = branch(
            b'b',
            vec![(member.clone(), LeafRecord::new(active_update_leaf))],
        );
        assert!(matches!(
            plan(&registry, &[&stale_base, &active_update]),
            Err(MergeError::UncertifiedDevice(_))
        ));

        // A stale higher-generation leaf never replaces an active leaf, and
        // never justifies a self-update; with the stale leaf as base the plan aborts.
        for (first_leaf, second_leaf, aborts) in [
            (active_leaf.clone(), stale_leaf.clone(), false),
            (stale_leaf.clone(), active_leaf.clone(), true),
        ] {
            let first = branch(b'a', vec![(member.clone(), LeafRecord::new(first_leaf))]);
            let second = branch(b'b', vec![(member.clone(), LeafRecord::new(second_leaf))]);
            match plan(&registry, &[&first, &second]) {
                Err(_) => assert!(aborts, "active base leaf was rejected"),
                Ok(ordered) => {
                    assert!(!aborts, "stale base leaf superseded an active leaf");
                    assert_eq!(ordered.members[&member].leaf, active_leaf);
                    assert!(!ordered.required_self_updates.contains(&member));
                }
            }
        }

        // If every branch holds a stale certificate, remove the resolved leaf.
        let stale1 = branch(
            b'c',
            vec![(member.clone(), LeafRecord::new(stale_base_leaf))],
        );
        let stale2 = branch(
            b'd',
            vec![(member.clone(), LeafRecord::new(stale_leaf.clone()))],
        );
        let revoked = plan(&registry, &[&stale1, &stale2]).unwrap();
        assert_eq!(revoked.removes, vec![member.clone()]);
        assert!(!revoked.members.contains_key(&member));
        assert!(revoked.required_self_updates.is_empty());

        // A stale leaf present only as a losing-branch Add is dropped without
        // a Remove for a leaf the base never held.
        let empty_base = branch(b'e', vec![]);
        let stale_add = branch(
            b'f',
            vec![(
                member.clone(),
                LeafRecord::new(stale_leaf).with_origin(LeafOrigin::Add),
            )],
        );
        let dropped = plan(&registry, &[&empty_base, &stale_add]).unwrap();
        assert!(dropped.removes.is_empty());
        assert!(dropped.adds.is_empty());
        assert!(!dropped.members.contains_key(&member));
        assert_eq!(registry.inactive_members(&stale_add), vec![member]);
    }

    #[test]
    fn revocation_deactivates_a_certified_device() {
        let (master, self_signing, device) = (key(b'm'), key(b's'), key(b'd'));
        let mut registry = DeviceRootRegistry::new([(PRINCIPAL.to_owned(), public(&master))]);
        registry.install_root(root(1, &self_signing)).unwrap();
        registry
            .certify(PRINCIPAL, &certificate(&master, &self_signing, &device))
            .unwrap();
        let live = leaf("hpke", 0, &device);
        assert!(registry.is_active(&live));
        registry.revoke(&public(&device));
        assert!(!registry.is_active(&live));
        assert!(registry.identity_of(&live).is_ok());
        assert!(registry.require_active(&live).is_err());
    }
}
