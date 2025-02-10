require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = new PrismaClient();
const app = express();
app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("Forms API is running!");
});

app.post('/jwt', async (req, res) => {
  const user= req.body;
  const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15d' });
  res.send({ token });
})
const verifyToken = (req, res, next) => {
  console.log('inside verify token', req.headers.authorization);
  if (!req.headers.authorization) {
    return res.status(401).send({ message: 'unauthorized access' });
  }
  const token = req.headers.authorization.split(' ')[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'unauthorized access' })
    }
    req.decoded = decoded;
    next();
  })
}
const verifyAdmin = async (req, res, next) => {
  try {
    // Ensure the user is authenticated
    if (!req.user || !req.user.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Find user in the database
    const user = await prisma.user.findUnique({
      where: { email: req.user.email },
    });

    // Check if user is an admin
    if (!user || user.isAdmin !== TRUE) {
      return res.status(403).json({ message: 'Forbidden: Admin access only' });
    }

    next(); // Proceed to next middleware
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
};
app.get("/users", verifyAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch users" });
  }
});
// Get user and check if the user is an admin
app.get('/users/admin/:email', verifyToken, async (req, res) => {
  const email = req.params.email;

  // Check if the user is authorized to check this user's admin status
  if (email !== req.decoded.email) {
    return res.status(403).send({ message: 'Forbidden access' });
  }

  try {
    // Query the user by email using Prisma
    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    // If the user exists, check if the user is an admin
    if (user) {
      return res.send({ admin: user.isAdmin });
    } else {
      return res.status(404).send({ message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: 'Internal server error' });
  }
});
app.post("/users", async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
      // Check if username already exists
      const existingUser = await prisma.user.findUnique({
        where: { username },
      });
  
      if (existingUser) {
        return res.status(400).json({ error: "Username already taken" });
      }
  
      // Check if email already exists
      const existingEmail = await prisma.user.findUnique({
        where: { email },
      });
  
      if (existingEmail) {
        return res.status(400).json({ error: "Email already in use" });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create the user
      const user = await prisma.user.create({
        data: { 
          username, 
          email, 
          passwordHash: hashedPassword 
        },
      });
  
      res.json(user);
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(400).json({ error: "User creation failed" });
    }
  });
  
app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});
