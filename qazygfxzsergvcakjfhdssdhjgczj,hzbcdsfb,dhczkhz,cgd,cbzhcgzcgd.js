let token=null;
async function login(){
  const pw=document.getElementById('password').value;
  const r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const j=await r.json();
  if(j.ok){token=j.token;document.getElementById('controls').style.display='block';refreshList();}
  else document.getElementById('loginStatus').innerText="Fail";
}
async function refreshList(){
  const r=await fetch('/admin/list',{headers:{'Authorization':'Bearer '+token}});
  const j=await r.json();
  let h='<table><tr><th>User</th><th>Room</th></tr>';
  for(const u of j.users)h+=`<tr><td>${u.username}</td><td>${u.room}</td></tr>`;
  h+='</table>';document.getElementById('users').innerHTML=h;
}
async function kick(){await act('/admin/kick')}
async function ban(){await act('/admin/ban')}
async function unban(){await act('/admin/unban')}
async function act(url){
  const u=document.getElementById('targetUser').value;
  await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({username:u})});
  refreshList();
}
async function broadcast(){
  const m=document.getElementById('bcMsg').value;
  await fetch('/admin/broadcast',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({message:m})});
}
async function createPoll(){
  const q=document.getElementById('pollQ').value;
  const opts=document.getElementById('pollOpts').value.split(',').map(x=>x.trim());
  await fetch('/admin/poll',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({question:q,options:opts})});
}
async function showResults(){
  const r=await fetch('/admin/poll/results',{headers:{'Authorization':'Bearer '+token}});
  const j=await r.json();document.getElementById('pollRes').innerText=JSON.stringify(j,null,2);
}
