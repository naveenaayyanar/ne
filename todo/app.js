"""
const form = document.getElementById('todo-form');
const input = document.getElementById('new-todo');
const list = document.getElementById('todo-list');

function load() {
  const items = JSON.parse(localStorage.getItem('todos') || '[]');
  list.innerHTML = '';
  items.forEach((it, idx) => {
    const li = document.createElement('li');
    li.textContent = it.text;
    if (it.done) li.classList.add('done');
    li.onclick = () => toggle(idx);
    const del = document.createElement('button');
    del.textContent = 'x';
    del.onclick = (e) => { e.stopPropagation(); remove(idx); };
    li.appendChild(del);
    list.appendChild(li);
  });
}

function save(items) { localStorage.setItem('todos', JSON.stringify(items)); }
function add(text) {
  const items = JSON.parse(localStorage.getItem('todos') || '[]');
  items.push({text, done:false});
  save(items); load();
}
function toggle(i) {
  const items = JSON.parse(localStorage.getItem('todos') || '[]');
  items[i].done = !items[i].done; save(items); load();
}
function remove(i) {
  const items = JSON.parse(localStorage.getItem('todos') || '[]');
  items.splice(i,1); save(items); load();
}

form.onsubmit = (e) => { e.preventDefault(); if (input.value.trim()) { add(input.value.trim()); input.value=''; } };
load();
"""
