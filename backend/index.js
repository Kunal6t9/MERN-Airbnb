const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
require("dotenv").config();
const User = require("./models/User.models.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookie = require("cookie-parser");

const app = express();
const bcryptSalt = bcrypt.genSaltSync(10);

// middlewares
app.use(express.json());
app.use(cookie());
app.use(
  cors({
    credentials: true,
    origin: "http://localhost:5173",
  })
);

// connect db
mongoose
  .connect(process.env.MONGODB)
  .then(() => console.log("Connected to Database"))
  .catch((err) => console.error("MongoDB connection error:", err));

// register
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const userDoc = await User.create({
      name,
      email,
      password: bcrypt.hashSync(password, bcryptSalt),
    });

    res.json(userDoc);
  } catch (error) {
    res.status(500).json({ message: error });
  }
});

// login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const userDoc = await User.findOne({ email });
  if (userDoc) {
    const correct_pass = bcrypt.compareSync(password, userDoc.password);
    if (correct_pass) {
      jwt.sign(
        {email: userDoc.email, id: userDoc._id, name:userDoc.name},
        process.env.JWT_SECRET,
        {},
        (err, token) => {
          if (err) throw err;
          res.cookie("token", token).json(userDoc);
        }
      );
    } else {
      res.status(400).json({ message: "Incorrect pass" });
    }
  } else {
    res.status(400).json({ message: "User Not found" });
  }
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies;
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, {}, async (err, userData) => {
      if (err) throw err;
      const {name,email,_id} = await User.findById(userData.id);
      res.json({name,email,_id});
    });
  } else {
    res.json(null);
  }
});

app.post("/logout" , (req,res) => {
  res.cookie('token','').json(true);
});

app.listen(3000, () => {
  console.log("Server is running at Port 3000");
});
