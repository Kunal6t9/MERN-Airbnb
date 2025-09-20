const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
require("dotenv").config();
const User = require("./models/user.models.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");


const app = express();
const bcryptSalt = bcrypt.genSaltSync(10);

// configure middlewares
app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: "http://localhost:5173",
  })
);

// connect DB
mongoose
  .connect(process.env.MONGODB)
  .then(() => console.log("Connected to Database"))
  .catch((err) => console.error("MongoDB connection error:", err));


// register user
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
 try{
   const userDoc= await User.create({
    name,
    email,
    password: bcrypt.hashSync(password,bcryptSalt),
  });

  res.json(userDoc);
 } catch (error) {
   res.status(500).json({message:error})
 }
});

// login user
app.post("/login", async(req,res) => {
  const {email,password} = req.body;
  const userDoc = await User.findOne({email});
  if(userDoc) {
    const correct_pass = bcrypt.compareSync(password,userDoc.password)
    if(correct_pass){
      jwt.sign({email:userDoc.email , id:userDoc._id},process.env.JWT_SECRET,{},(err,token) => {
        if(err) throw err;
        res.cookie('token',token).json({message:"Correct pass"});
      });
    } else {
      res.status(400).json({message:"Incorrect pass"})
    }
  } else {
    res.json({message:"User Not found"});
  }
})

// server 
app.listen(3000, () => {
  console.log("Server is running at Port 3000");
});
