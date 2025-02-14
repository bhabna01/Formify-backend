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
    console.log('Decoded Token:', decoded);
    next();
  })
}


const verifyAdmin = async (req, res, next) => {
  try {
      if (!req.decoded || !req.decoded.email) {
          return res.status(401).json({ message: 'Unauthorized' });
      }

      console.log('Admin Check: Fetching user with email:', req.decoded.email);

      const user = await prisma.user.findUnique({
          where: { email: req.decoded.email },
      });

      console.log('User found:', user); // Log user data

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      if (user.isAdmin !== true) {  // Ensure isAdmin is boolean true
          return res.status(403).json({ message: 'Forbidden: Admin access only' });
      }

      next();
  } catch (error) {
      console.error('Error in verifyAdmin:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
};



app.get("/users", verifyToken,verifyAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch users" });
  }
});
app.patch("/users/block/:userId",verifyToken, verifyAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
    const user = await prisma.user.update({
      where: { id: Number(userId) },
      data: { isBlocked: true },
    });
    res.json({ message: "User blocked", user });
  } catch (error) {
    res.status(400).json({ error: "Error blocking user" });
  }
});

// Unblock user
app.patch("/users/unblock/:userId", verifyToken,verifyAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
    const user = await prisma.user.update({
      where: { id: Number(userId) },
      data: { isBlocked: false },
    });
    res.json({ message: "User unblocked", user });
  } catch (error) {
    res.status(400).json({ error: "Error unblocking user" });
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
 // Delete user
app.delete("/users/:userId", verifyToken, verifyAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
      await prisma.user.delete({ where: { id: Number(userId) } });
      res.json({ message: "User deleted successfully" });
  } catch (error) {
      console.error("Error deleting user:", error);
      res.status(400).json({ error: "Error deleting user" });
  }
});

// Add admin role
app.patch("/users/admin/:userId", verifyToken, verifyAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
      const user = await prisma.user.update({
          where: { id: Number(userId) },
          data: { isAdmin: true },
      });
      res.json({ message: "User promoted to admin", user });
  } catch (error) {
      console.error("Error promoting user:", error);
      res.status(400).json({ error: "Error promoting user" });
  }
});

// Remove admin role
app.patch("/users/remove-admin/:userId", verifyToken, verifyAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
      const user = await prisma.user.update({
          where: { id: Number(userId) },
          data: { isAdmin: false },
      });
      res.json({ message: "User demoted from admin", user });
  } catch (error) {
      console.error("Error demoting user:", error);
      res.status(400).json({ error: "Error demoting user" });
  }
}); 

app.post("/templates", verifyToken, verifyAdmin, async (req, res) => {
  try {
      const { title, description, topic, isPublic, tags, questions } = req.body;
      
      // Create template with author connection
      const newTemplate = await prisma.template.create({
        data: {
          title,
          description,
          topic,
          isPublic,
          author: {
            connect: { email: req.decoded.email }  // Use email instead of userId
          },
          tags: {
            connectOrCreate: tags.map(tag => ({
              where: { name: tag },
              create: { name: tag },
            })),
          },
          questions: {
            create: questions.map(question => ({
              title: question.title,
              description: question.description,
              type: question.type,
              orderIndex: question.orderIndex,
              isRequired: question.isRequired,
            }))
          }
        },
        include: { 
          tags: true, 
          questions: true  // Include questions in the response
        },
      });

      res.status(201).json({ message: "Template created successfully", template: newTemplate });
  } catch (error) {
      console.error("Error creating template:", error);
      res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/templates", async (req, res) => {
  try {
    const templates = await prisma.template.findMany({
      include: { tags: true, author: true },
    });
    res.json(templates);
  } catch (error) {
    console.error("Error fetching templates:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// app.get("/templates/:id", async (req, res) => {
//   const { id } = req.params;
//   try {
//     const template = await prisma.template.findUnique({
//       where: { id: parseInt(id) },
//       include: { questions: true }, // Include questions if needed
//     });

//     if (!template) {
//       return res.status(404).json({ error: "Template not found" });
//     }

//     res.json(template);
//   } catch (error) {
//     console.error("Error fetching template:", error);
//     res.status(500).json({ error: "Internal Server Error" });
//   }
// });
app.get("/templates/:id", async (req, res) => {
  const { id } = req.params; // id is already a string, but Prisma can handle it directly if it's in the correct format

  try {
    const template = await prisma.template.findUnique({
      where: {
        id: parseInt(id, 10), // Convert the string to an integer, but you can avoid this if you're sure it's an integer
      },
      include: {
        questions: true,
      },
    });

    if (!template) {
      return res.status(404).json({ message: "Template not found" });
    }

    res.json(template);
  } catch (error) {
    console.error("Error fetching template:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// form
app.post("/forms/:templateId", verifyToken, async (req, res) => {
  const { templateId } = req.params;
  const { answers } = req.body; 
  
  try {
    // Check if the template exists
    const template = await prisma.template.findUnique({
      where: { id: Number(templateId) },
      include: { questions: true }, // Include questions to validate the answers
    });
    
    if (!template) {
      return res.status(404).json({ error: "Template not found" });
    }

    // Create a new form entry
    const newForm = await prisma.form.create({
      data: {
        templateId: template.id,
        userId: req.decoded.email,  // Assuming you store the userId in decoded token
        answers: {
          create: answers.map((answer) => ({
            value: answer.value,
            questionId: answer.questionId,
          })),
        },
      },
    });

    res.status(201).json({ message: "Form submitted successfully", form: newForm });
  } catch (error) {
    console.error("Error submitting form:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});
