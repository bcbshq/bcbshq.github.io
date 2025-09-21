/* modules/mappings/module.js */
export function renderMappings(container, mappings){
  container.innerHTML = '<pre>'+JSON.stringify(mappings, null, 2)+'</pre>';
}
