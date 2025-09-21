/* modules/techniques/matrix.js - matrix helpers */
export function simpleMatrix(techniques){
  // produce a simple mapping by tactic
  const out = {};
  techniques.forEach(t => { out[t.tactic] = out[t.tactic] || []; out[t.tactic].push(t.id); });
  return out;
}
