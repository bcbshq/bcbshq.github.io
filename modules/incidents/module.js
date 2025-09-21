/* modules/incidents/module.js */
export function renderIncidents(container, incidents){
  container.innerHTML = '<pre>'+JSON.stringify(incidents, null, 2)+'</pre>';
}
