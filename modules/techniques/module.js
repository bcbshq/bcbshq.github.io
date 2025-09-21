/* modules/techniques/module.js */
export function renderTechniques(container, techniques){
  container.innerHTML = '<pre>'+JSON.stringify(techniques, null, 2)+'</pre>';
}
