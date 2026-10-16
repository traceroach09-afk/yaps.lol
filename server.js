// Small dependency-free server for yaps.lol. Run with: node server.js
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = __dirname;
const dataDir = path.join(root, 'data');
const dbFile = path.join(dataDir, 'db.json');
const port = Number(process.env.PORT || 3000);
const sessions = new Map();
const mime = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.json':'application/json; charset=utf-8', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.svg':'image/svg+xml', '.webp':'image/webp', '.ico':'image/x-icon' };
fs.mkdirSync(dataDir, { recursive: true });
function readDb(){ try { return JSON.parse(fs.readFileSync(dbFile,'utf8')); } catch { return { users:[], templates:[] }; } }
let db = readDb();
function writeDb(){ const tmp=dbFile+'.tmp'; fs.writeFileSync(tmp,JSON.stringify(db,null,2)); fs.renameSync(tmp,dbFile); }
function json(res,status,data,headers={}){ res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}); res.end(JSON.stringify(data)); }
function body(req){ return new Promise((resolve,reject)=>{ let raw=''; req.on('data',c=>{raw+=c; if(raw.length>6*1024*1024){reject(new Error('Request too large'));req.destroy();}}); req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{});}catch{reject(new Error('Invalid JSON'));}}); req.on('error',reject); }); }
function cookies(req){ return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2)); }
function currentUser(req){ const token=cookies(req).yaps_session; const uid=token&&sessions.get(token); return db.users.find(u=>u.id===uid)||null; }
function publicUser(u){ return u?{username:u.username,createdAt:u.createdAt}:null; }
function defaultProfile(username){ return {name:username,display:'',description:'just doing my thing ✦',accent:'#ff862e',text:'#ffffff',background:'#080808',icon:'#ffffff',opacity:94,blur:0,glowColor:'#ff862e',glowStrength:75,fontFamily:'Space Grotesk',cardRadius:16,yapperStatus:'',yapperPresence:'online',backgroundEffect:'none',profileGradient:false,views:0,links:[],glows:{username:true,socials:false,badges:false},favorites:[],recent:[],uploads:[],customTemplates:[],toggles:{monochrome:true,animated:false,swap:false,volume:false,yapperAvatar:false,avatarDecoration:true,mfa:false}}; }
function passwordHash(password,salt=crypto.randomBytes(16).toString('hex')){ return {salt,hash:crypto.scryptSync(password,salt,64).toString('hex')}; }
function safeProfile(p){ if(!p||typeof p!=='object'||Array.isArray(p))return null; const out={...p}; delete out.password; delete out.email; out.views=Math.max(0,Number(out.views)||0); out.name=String(out.name||'').slice(0,24); return out; }
function slug(s){ return String(s||'').toLowerCase().replace(/[^a-z0-9_.-]/g,''); }
const server=http.createServer(async(req,res)=>{
  const u=new URL(req.url,'http://localhost'); const p=decodeURIComponent(u.pathname);
  try {
    if(req.method==='GET'&&p==='/api/me'){ const user=currentUser(req); return json(res,200,{user:publicUser(user)}); }
    if(req.method==='POST'&&(p==='/api/register'||p==='/api/login')){
      const b=await body(req); const username=slug(b.username); const pass=String(b.password||'');
      if(p==='/api/register'){
        if(!/^[a-z0-9_.-]{3,24}$/.test(username))return json(res,400,{error:'Choose a username with 3–24 letters, numbers, dots, dashes, or underscores.'});
        if(pass.length<8)return json(res,400,{error:'Password must be at least 8 characters.'});
        if(db.users.some(x=>x.username.toLowerCase()===username.toLowerCase()))return json(res,409,{error:'That username is already taken.'});
        const pw=passwordHash(pass); const user={id:crypto.randomUUID(),username,...pw,createdAt:new Date().toISOString(),profile:defaultProfile(username),favorites:[]}; db.users.push(user); writeDb();
        const token=crypto.randomBytes(32).toString('hex'); sessions.set(token,user.id); return json(res,201,{user:publicUser(user)},{'Set-Cookie':`yaps_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`});
      }
      const user=db.users.find(x=>x.username.toLowerCase()===username.toLowerCase()); if(!user)return json(res,401,{error:'Username or password is incorrect.'});
      const actual=crypto.scryptSync(pass,user.salt,64).toString('hex'); if(!crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(user.hash,'hex')))return json(res,401,{error:'Username or password is incorrect.'});
      const token=crypto.randomBytes(32).toString('hex'); sessions.set(token,user.id); return json(res,200,{user:publicUser(user)},{'Set-Cookie':`yaps_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`});
    }
    if(req.method==='POST'&&p==='/api/logout'){ const c=cookies(req);sessions.delete(c.yaps_session);return json(res,200,{ok:true},{'Set-Cookie':'yaps_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'}); }
    if(p.startsWith('/api/')){
      const user=currentUser(req);
      if(req.method==='GET'&&p==='/api/templates')return json(res,200,{templates:db.templates.map(t=>({...t,favorited:!!user&&user.favorites.includes(t.id)}))});
    if(req.method==='GET'&&p.startsWith('/api/profiles/')){ const username=slug(p.slice('/api/profiles/'.length));const found=db.users.find(x=>x.username.toLowerCase()===username.toLowerCase());if(!found)return json(res,404,{error:'Profile not found.'});found.profile.views=(Number(found.profile.views)||0)+1;writeDb();return json(res,200,{profile:found.profile}); }
      if(!user)return json(res,401,{error:'Sign in to continue.'});
      if(req.method==='GET'&&p==='/api/profile')return json(res,200,{profile:user.profile});
      if(req.method==='PUT'&&p==='/api/profile'){const b=await body(req);const profile=safeProfile(b.profile);if(!profile)return json(res,400,{error:'Profile data is invalid.'});user.profile={...defaultProfile(user.username),...profile,name:user.username};writeDb();return json(res,200,{profile:user.profile});}
      if(req.method==='POST'&&p==='/api/templates'){const b=await body(req);const name=String(b.name||'').trim().slice(0,40);if(!name||!b.config)return json(res,400,{error:'Add a template name and style.'});const t={id:crypto.randomUUID(),name,author:user.username,tags:String(b.tags||'community · custom').slice(0,80),config:b.config,uses:0,createdAt:new Date().toISOString()};db.templates.unshift(t);writeDb();return json(res,201,{template:t});}
      const tm=p.match(/^\/api\/templates\/([a-f0-9-]+)\/(favorite|view)$/); if(req.method==='POST'&&tm){const t=db.templates.find(x=>x.id===tm[1]);if(!t)return json(res,404,{error:'Template not found.'});if(tm[2]==='favorite'){const i=user.favorites.indexOf(t.id);if(i<0)user.favorites.push(t.id);else user.favorites.splice(i,1);writeDb();return json(res,200,{favorited:i<0});}t.uses++;writeDb();return json(res,200,{uses:t.uses});}
      return json(res,404,{error:'API route not found.'});
    }
    let file=p==='/'?path.join(root,'index.html'):path.resolve(root,'.'+p); const allowed=file===path.join(root,'index.html')||file===path.join(root,'dashboard.html')||file===path.join(root,'profile.html')||file===path.join(root,'local-auth.js')||file.startsWith(path.join(root,'assets')+path.sep); if(!allowed)return json(res,404,{error:'Not found.'});
    if(!fs.existsSync(file)||!fs.statSync(file).isFile())return json(res,404,{error:'Not found.'});
    res.writeHead(200,{'Content-Type':mime[path.extname(file).toLowerCase()]||'application/octet-stream','X-Content-Type-Options':'nosniff'});fs.createReadStream(file).pipe(res);
  } catch(e){ json(res,400,{error:e.message||'Request failed.'}); }
});
server.listen(port,'0.0.0.0',()=>console.log(`yaps.lol is available at http://localhost:${port} (network: http://<this-device-ip>:${port})`));
