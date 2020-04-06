/* Deposit lock
 * 
 * This lock is designed to only works with NervosDAO cells,
 * other usage will causes the cell be locked forever.
 *
 * Motivation:
 * This lock is designed to enforce users to destroy WCKB to get their native CKB back,
 * in withdraw phase1 a user must destroy X WCKB, which correspond to the original deposited CKB.
 * in withdraw phase2 a user must destroy Y WCKB which correspond to the NervosDAO compensation.
 * we also set a timeout after the withdraw phase1, after W blocks, if the user do not perform phase2, 
 * anyone can destroy Y WCKB to get unlock the NervosDAO cell.
 *
 * Unlock conditions:
 *
 * phase1:
 * 1. check `inputs WCKB - outputs WCKB = X`.
 * 2. has exactly one output cell that do not has the type field.
 *
 * phase2:
 * 1. check `inputs WCKB - outputs WCKB = Y`.
 * 2. at least one input cell that do not has the type field is from the same transaction.
 * or:
 * 2. the since field of inputs is set to relatively `W` blocks.
 *
 * HINT: we use a cell as unlock proof to break the restriction of NervosDAO.
 *
 * Args:
 * This script accept 32 bytes args: <wckb type hash>
 * <wckb type hash>: blake2b(Script(hash_type: Type, code_hash: <wckb type id>))
 */

int main() { return 0; }
