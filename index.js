import express from "express";
import cors from "cors";
import http from "http";
import { Server } from "socket.io";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "DEV_ONLY_CHANGE_ME";
const DB_FILE = process.env.DB_FILE || path.join(process.cwd(), "server", "data.json");
const app = express();
const server = http.createServer(app);
app.use(cors({ origin: process.env.CLIENT_ORIGIN || "*", credentials: false }));
app.use(express.json({limit:"1mb"}));

const emptyDb = () => ({users:[],messages:[],gifts:[],usernameListings:[],nextAnon:100000});
let db = emptyDb();
let writeQueue = Promise.resolve();
async function loadDb(){
  try { db = {...emptyDb(), ...JSON.parse(await fs.readFile(DB_FILE,"utf8"))}; }
  catch(e) { await fs.mkdir(path.dirname(DB_FILE),{recursive:true}); await saveDb(); }
}
function saveDb(){
  writeQueue = writeQueue.then(async()=>{await fs.mkdir(path.dirname(DB_FILE),{recursive:true});const tmp=DB_FILE+".tmp";await fs.writeFile(tmp,JSON.stringify(db,null,2));await fs.rename(tmp,DB_FILE)}).catch(e=>console.error("DB write failed",e));
  return writeQueue;
}
const io = new Server(server,{cors:{origin:"*",methods:["GET","POST"]}});
function publicUser(u){return {id:u.id,username:u.username,displayName:u.displayName,avatar:u.avatar,anonNumber:u.anonNumber,createdAt:u.createdAt,ownedGifts:u.ownedGifts||[],bio:u.bio||""};}
function auth(req,res,next){
 const h=req.headers.authorization||"";
 try {const t=h.startsWith("Bearer ")?h.slice(7):"";req.user=jwt.verify(t,JWT_SECRET);next()}
 catch {res.status(401).json({error:"Нужно войти в аккаунт"})}
}
function sign(u){return jwt.sign({id:u.id},JWT_SECRET,{expiresIn:"30d"})}
function findUser(id){return db.users.find(u=>u.id===id)}
function socketAuth(socket,next){try{socket.user=jwt.verify(socket.handshake.auth?.token||"",JWT_SECRET);next()}catch{next(new Error("UNAUTHORIZED"))}}
io.use(socketAuth);
io.on("connection",socket=>{
 socket.join("user:"+socket.user.id);
 socket.on("join:conversation",({userId})=>{if(userId)socket.join("dm:"+[socket.user.id,userId].sort().join(":"))});
 socket.on("typing",({userId,typing})=>{if(userId)socket.to("user:"+userId).emit("typing",{from:socket.user.id,typing:!!typing})});
});

app.get("/api/health",(_req,res)=>res.json({ok:true,service:"Member API",version:1}));
app.post("/api/auth/register",async(req,res)=>{
 const {username,displayName,password}=req.body||{};
 const un=String(username||"").trim().replace(/^@/,"").toLowerCase();
 const name=String(displayName||"").trim().slice(0,40);
 if(!/^[a-z0-9_]{3,24}$/.test(un))return res.status(400).json({error:"Имя пользователя: 3–24 символа, латиница, цифры и _"});
 if(name.length<1)return res.status(400).json({error:"Укажи отображаемое имя"});
 if(typeof password!=="string"||password.length<8)return res.status(400).json({error:"Пароль должен содержать минимум 8 символов"});
 if(db.users.some(u=>u.username===un))return res.status(409).json({error:"Это имя пользователя уже занято"});
 const passwordHash=await bcrypt.hash(password,12);
 const u={id:crypto.randomUUID(),username:un,displayName:name,passwordHash,avatar:name.split(/\s+/).map(s=>s[0]).join("").slice(0,2).toUpperCase(),anonNumber:String(db.nextAnon++),createdAt:new Date().toISOString(),ownedGifts:[],bio:""};
 db.users.push(u);await saveDb();res.status(201).json({token:sign(u),user:publicUser(u)});
});
app.post("/api/auth/login",async(req,res)=>{
 const un=String(req.body?.username||"").trim().replace(/^@/,"").toLowerCase(),password=String(req.body?.password||"");
 const u=db.users.find(x=>x.username===un);
 if(!u||!(await bcrypt.compare(password,u.passwordHash)))return res.status(401).json({error:"Неверный логин или пароль"});
 res.json({token:sign(u),user:publicUser(u)});
});
app.get("/api/me",auth,(req,res)=>{const u=findUser(req.user.id);if(!u)return res.status(401).json({error:"Аккаунт не найден"});res.json({user:publicUser(u)})});
app.patch("/api/me",auth,async(req,res)=>{
 const u=findUser(req.user.id);if(!u)return res.status(404).json({error:"Аккаунт не найден"});
 if(typeof req.body.displayName==="string"&&req.body.displayName.trim())u.displayName=req.body.displayName.trim().slice(0,40);
 if(typeof req.body.bio==="string")u.bio=req.body.bio.slice(0,160);
 u.avatar=u.displayName.split(/\s+/).map(s=>s[0]).join("").slice(0,2).toUpperCase();
 await saveDb();res.json({user:publicUser(u)});
});
app.get("/api/users/search",auth,(req,res)=>{
 const q=String(req.query.q||"").replace(/^@/,"").toLowerCase();
 if(q.length<2)return res.json({users:[]});
 res.json({users:db.users.filter(u=>u.id!==req.user.id&&(u.username.includes(q)||u.displayName.toLowerCase().includes(q)||u.anonNumber.includes(q))).slice(0,20).map(publicUser)});
});
app.get("/api/conversations",auth,(req,res)=>{
 const uid=req.user.id;const latest=new Map();
 for(const m of db.messages){if(m.from===uid||m.to===uid){const other=m.from===uid?m.to:m.from;if(!latest.has(other)||latest.get(other).createdAt<m.createdAt)latest.set(other,m)}}
 const users=[...latest.keys()].map(id=>({user:findUser(id),last:latest.get(id)})).filter(x=>x.user).sort((a,b)=>b.last.createdAt.localeCompare(a.last.createdAt));
 res.json({conversations:users.map(x=>({user:publicUser(x.user),lastMessage:{text:x.last.text,createdAt:x.last.createdAt,from:x.last.from}}))});
});
app.get("/api/messages/:userId",auth,(req,res)=>{
 const other=req.params.userId;if(!findUser(other))return res.status(404).json({error:"Пользователь не найден"});
 const messages=db.messages.filter(m=>(m.from===req.user.id&&m.to===other)||(m.from===other&&m.to===req.user.id)).slice(-500);
 res.json({messages});
});
app.post("/api/messages",auth,async(req,res)=>{
 const to=String(req.body?.to||""),text=String(req.body?.text||"").trim();
 if(!findUser(to))return res.status(404).json({error:"Получатель не найден"});
 if(to===req.user.id)return res.status(400).json({error:"Нельзя отправить сообщение самому себе"});
 if(!text||text.length>5000)return res.status(400).json({error:"Сообщение должно содержать от 1 до 5000 символов"});
 const message={id:crypto.randomUUID(),from:req.user.id,to,text,createdAt:new Date().toISOString()};
 db.messages.push(message);await saveDb();
 io.to("user:"+to).emit("message:new",message);io.to("user:"+req.user.id).emit("message:new",message);
 res.status(201).json({message});
});
const giftCatalog=[
 {id:"star",name:"Звезда Member",emoji:"🌟",description:"Коллекционный подарок поддержки",price:100},
 {id:"rose",name:"Неоновая роза",emoji:"🌹",description:"Для особенного человека",price:250},
 {id:"ghost",name:"Призрачный кот",emoji:"👻",description:"Редкий цифровой сувенир",price:500},
 {id:"crown",name:"Корона Member",emoji:"👑",description:"Легендарный подарок",price:1000},
 {id:"crystal",name:"Кристалл ночи",emoji:"💎",description:"Коллекция тёмной темы",price:750}
];
app.get("/api/gifts",(_req,res)=>res.json({gifts:giftCatalog,notice:"Демонстрационный каталог. Это не блокчейн-NFT."}));
app.get("/api/market/usernames",(_req,res)=>res.json({listings:db.usernameListings.map(l=>({...l,seller:publicUser(findUser(l.sellerId)||{id:"",username:"unknown",displayName:"Неизвестный"})}))}));
app.post("/api/market/usernames",auth,async(req,res)=>{
 const username=String(req.body?.username||"").trim().replace(/^@/,"").toLowerCase(),price=Number(req.body?.price);
 if(!/^[a-z0-9_]{3,24}$/.test(username))return res.status(400).json({error:"Некорректный username"});
 if(!Number.isFinite(price)||price<1||price>1000000)return res.status(400).json({error:"Цена должна быть от 1 до 1 000 000 условных кредитов"});
 if(db.users.some(u=>u.username===username)||db.usernameListings.some(l=>l.username===username))return res.status(409).json({error:"Этот username занят или уже выставлен"});
 const listing={id:crypto.randomUUID(),username,price,sellerId:req.user.id,createdAt:new Date().toISOString(),demo:true};db.usernameListings.push(listing);await saveDb();res.status(201).json({listing});
});
app.post("/api/market/usernames/:id/buy",auth,async(req,res)=>{
 const listing=db.usernameListings.find(l=>l.id===req.params.id);if(!listing)return res.status(404).json({error:"Лот не найден"});
 if(listing.sellerId===req.user.id)return res.status(400).json({error:"Нельзя купить собственный лот"});
 // Purchase is intentionally simulated: no wallet, money or real username transfer.
 res.status(501).json({error:"Покупка пока демонстрационная. Реальные сделки требуют кошелька, оплаты и механизма передачи username."});
});
app.post("/api/gifts/send",auth,async(req,res)=>{
 const {to,giftId}=req.body||{};const gift=giftCatalog.find(g=>g.id===giftId);
 if(!findUser(to))return res.status(404).json({error:"Получатель не найден"});
 if(!gift)return res.status(400).json({error:"Подарок не найден"});
 const item={id:crypto.randomUUID(),giftId:gift.id,name:gift.name,emoji:gift.emoji,from:req.user.id,to,createdAt:new Date().toISOString(),collectible:true,chain:"off-chain-demo"};
 db.gifts.push(item);const recipient=findUser(to);recipient.ownedGifts=recipient.ownedGifts||[];recipient.ownedGifts.push(item.id);await saveDb();
 io.to("user:"+to).emit("gift:new",item);res.status(201).json({gift:item,notice:"Подарок сохранён как внутренняя коллекционная запись, не on-chain NFT."});
});
app.get("/api/gifts/mine",auth,(req,res)=>res.json({gifts:db.gifts.filter(g=>g.to===req.user.id||g.from===req.user.id)}));
app.get("/api/market/anon-number",auth,(req,res)=>{const u=findUser(req.user.id);res.json({anonNumber:u.anonNumber,notice:"Номер анонимности Member — внутренний ID, не телефон и не гарантия полной анонимности."})});
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:"Внутренняя ошибка сервера"})});
await loadDb();
server.listen(PORT,()=>console.log(`Member API listening on ${PORT}`));
