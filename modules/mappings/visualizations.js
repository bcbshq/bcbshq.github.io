/* modules/mappings/visualizations.js - placeholder for graph visualizations */
export function simpleList(mappings){
  return mappings.map(m => m.actor + ' → ' + m.malware).join('\\n');
}
