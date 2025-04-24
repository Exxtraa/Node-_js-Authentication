import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";

// Required for __dirname in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MongoDB connection
mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "shitt",
  })
  .then(() => console.log("Database Connected"))
  .catch((e) => console.log(e));

// MongoDB Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

// App setup
const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("view engine", "ejs");

// Auth Middleware
const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decoded = jwt.verify(token, "sstty");
    req.user = await User.findById(decoded._id);
    next();
  } else {
    res.redirect("/login");
  }
};

// Routes
app.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { name: req.user.name });
});

app.get("/login", (req, res) => {
  res.render("login", { message: null });
});

app.get("/register", (req, res) => {
  res.render("register", { message: null });
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  let user = await User.findOne({ email });

  if (user) {
    return res.render("register", { message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password,10);

  user = await User.create({ name, email, password:hashedPassword });

  const token = jwt.sign({ _id: user._id }, "sstty");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });

  res.redirect("/");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.redirect("/register");
  }

  const isMatch = await bcrypt.compare(password,user.password);

  if (!isMatch) {
    return res.render("login", { email, message: "Incorrect password" });
  }

  const token = jwt.sign({ _id: user._id }, "sstty");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });

  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/login");
});

// Server
app.listen(5000, () => {
  console.log("Server is running on http://localhost:5000");
});
