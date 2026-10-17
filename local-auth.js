async function deriveLocalPassword(password,salt){
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'},key,256);
  return Array.from(new Uint8Array(bits),b=>b.toString(16).padStart(2,'0')).join('');
}
function localUsers(){try{return JSON.parse(localStorage.getItem('yaps-local-users')||'[]')}catch{return[]}}
async function createLocalAccount(username,password){
  username=username.trim();
  if(!/^[A-Za-z0-9_.-]{3,24}$/.test(username))throw Error('Use 3–24 letters, numbers, dots, dashes, or underscores.');
  if(password.length<8)throw Error('Password must be at least 8 characters.');
  const users=localUsers();
  if(users.some(u=>u.username.toLowerCase()===username.toLowerCase()))throw Error('That username already exists in this browser.');
  if(!crypto.subtle)throw Error('This browser cannot securely store local accounts. Try a current browser version.');
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const hash=await deriveLocalPassword(password,salt);
  const saltText=Array.from(salt,b=>b.toString(16).padStart(2,'0')).join('');
  users.push({username,salt:saltText,hash});
  localStorage.setItem('yaps-local-users',JSON.stringify(users));
  const profile={name:username,views:0,links:[],favorites:[],recent:[],customTemplates:[],toggles:{monochrome:true,animated:false,swap:false,volume:false,yapperAvatar:false,avatarDecoration:true}};
  localStorage.setItem('yaps-active-user',username);
  localStorage.setItem('yaps-profile:'+username,JSON.stringify(profile));
  localStorage.setItem('guns-demo',JSON.stringify(profile));
}
async function loginLocalAccount(username,password){
  const user=localUsers().find(u=>u.username.toLowerCase()===username.trim().toLowerCase());
  if(!user)throw Error('No local account with that username was found in this browser.');
  const salt=Uint8Array.from(user.salt.match(/.{2}/g),b=>parseInt(b,16));
  if(await deriveLocalPassword(password,salt)!==user.hash)throw Error('That password is incorrect.');
  localStorage.setItem('yaps-active-user',user.username);
  const profile=localStorage.getItem('yaps-profile:'+user.username)||JSON.stringify({name:user.username,views:0,links:[]});
  localStorage.setItem('yaps-profile:'+user.username,profile);
  localStorage.setItem('guns-demo',profile);
}
