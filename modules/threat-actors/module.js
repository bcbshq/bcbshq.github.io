/* modules/threat-actors/module.js - render threat actors tab content */
export function renderThreatActors(container, actors){
  container.innerHTML = '<pre>'+JSON.stringify(actors, null, 2)+'</pre>';
}
