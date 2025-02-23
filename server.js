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
app.get("/users/email/:email", async (req, res) => {
  const { email } = req.params;
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
      return res.status(404).json({ error: "User not found" });
  }

  res.json({ is_blocked: user.isBlocked });
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
    const userEmail = req.decoded.email;

    // Get user first
    const user = await prisma.user.findUnique({
      where: { email: userEmail },
      select: { id: true }
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Create template with relations
    const newTemplate = await prisma.template.create({
      data: {
        title,
        description,
        topic,
        isPublic,
        authorId: user.id,
        tags: {
          connectOrCreate: tags.map(tag => ({
            where: { name: tag.trim() },
            create: { name: tag.trim() }
          }))
        },
        questions: {
          create: questions.map(q => ({
            title: q.title,
            description: q.description,
            type: q.type,
            orderIndex: q.orderIndex,
            isRequired: q.isRequired,
            // options: q.type === "text" ? null : q.options
            options: q.type === "text" ? null : JSON.stringify(q.options) 
          }))
        }
      },
      include: { 
        tags: true,
        questions: true
      }
    });

    res.status(201).json({ template: newTemplate });
  } catch (error) {
    console.error("Error creating template:", error);
    res.status(500).json({ 
      error: "Failed to create template",
      details: error.message
    });
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
app.get("/templates/latest", async (req, res) => {
  try {
    const latestTemplates = await prisma.template.findMany({
      orderBy: { createdAt: "desc" },
      take: 10, // Fetch latest 10 templates
      include: { author: true },
    });

    res.json(latestTemplates);
  } catch (error) {
    console.error("Error fetching latest templates:", error);
    res.status(500).json({ error: "Failed to fetch templates" });
  }
});
app.get("/templates/popular", async (req, res) => {
  try {
    const popularTemplates = await prisma.template.findMany({
      orderBy: { forms: { _count: "desc" } },
      take: 5, // Fetch top 5
      include: { author: true },
    });

    res.json(popularTemplates);
  } catch (error) {
    console.error("Error fetching popular templates:", error);
    res.status(500).json({ error: "Failed to fetch templates" });
  }
});
app.get("/tags", async (req, res) => {
  try {
    const tags = await prisma.tag.findMany({
      include: {
        templates: true, // Include number of templates for each tag
      },
    });

    const formattedTags = tags.map(tag => ({
      name: tag.name,
      count: tag.templates.length,
    }));

    res.json(formattedTags);
  } catch (error) {
    console.error("Error fetching tags:", error);
    res.status(500).json({ error: "Failed to fetch tags" });
  }
});




app.get("/templates/:templateId", async (req, res) => {
  try {
    const { templateId } = req.params;

    const template = await prisma.template.findUnique({
      where: { id: parseInt(templateId) },
      include: { questions: true },
    });

    if (!template) {
      return res.status(404).json({ error: "Template not found" });
    }

    const formattedTemplate = {
      ...template,
      questions: template.questions.map((q) => ({
        ...q,
        options: q.options ? JSON.parse(q.options) : [], // Ensure options are parsed
      })),
    };

    res.json(formattedTemplate);
  } catch (error) {
    console.error("Error fetching template:", error);
    res.status(500).json({ error: "Failed to fetch template" });
  }
});

app.post("/forms/:templateId", verifyToken, async (req, res) => {
  const { templateId } = req.params;
  const { answers } = req.body; 
  const userEmail = req.decoded.email; // Extract email from token

  try {
    // Find user by email to get user ID
    const user = await prisma.user.findUnique({
      where: { email: userEmail },
      select: { id: true }, // Get only the `id`
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the template exists
    const template = await prisma.template.findUnique({
      where: { id: Number(templateId) },
      include: { questions: true },
    });

    if (!template) {
      return res.status(404).json({ error: "Template not found" });
    }

    // Create a new form entry with the correct user ID
    const newForm = await prisma.form.create({
      data: {
        templateId: template.id,
        userId: user.id, // Use the integer user ID
        answers: {
          create: answers.map((answer) => ({
            value: Array.isArray(answer.value) ? JSON.stringify(answer.value) : answer.value, // Convert arrays to JSON strings
            questionId: answer.questionId,
          })),
        },
      },
    });

    res.status(201).json(newForm);
  } catch (error) {
    console.error("Error creating form:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});



app.get("/template/search", async (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).json({ error: "Query parameter is required" });

  try {
      const searchTerms = query
          .toString()
          .replace(/[^a-zA-Z0-9 ]/g, " ")
          .trim()
          .split(/\s+/)
          .filter(word => word.length > 2)
          .map(term => `${term}:*`)
          .join(" & ");

      const templates = await prisma.$queryRaw`
          SELECT 
            id,
            title,
            description,
            topic,
            "isPublic",
            "createdAt",
            "updatedAt",
            "authorId",
            ts_rank(search_vector, to_tsquery('english', ${searchTerms}))::float as rank
          FROM "Template"
          WHERE 
            search_vector @@ to_tsquery('english', ${searchTerms})
          ORDER BY rank DESC
          LIMIT 100
      `;

      res.json(templates);
  } catch (error) {
      console.error("❌ Search Error:", error);
      res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/admin/forms", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const forms = await prisma.form.findMany({
      include: {
        user: { select: { id: true, username: true, email: true } }, // Get user details
        answers: { include: { question: { select: { title: true } } } }, // Get answers with questions
        template: { select: { title: true } }, // Get template name
      },
    });

    res.json(forms);
  } catch (error) {
    console.error("Error fetching forms:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.patch("/templates/:templateId", verifyToken, verifyAdmin, async (req, res) => {
  const { templateId } = req.params;
  const { title, description, topic, isPublic, questions } = req.body;

  try {
    // Get existing template with questions
    const existingTemplate = await prisma.template.findUnique({
      where: { id: Number(templateId) },
      include: { questions: true }
    });

    if (!existingTemplate) {
      return res.status(404).json({ error: "Template not found" });
    }

    // Map existing question IDs
    const existingQuestionIds = existingTemplate.questions.map(q => q.id);

    // Process questions update
    const questionsUpdate = questions.map(question => ({
      where: { id: question.id || -1 }, // Use invalid ID for new questions
      create: {
        title: question.title,
        description: question.description,
        type: question.type,
        options: question.options ? JSON.stringify(question.options) : null
      },
      update: {
        title: question.title,
        description: question.description,
        type: question.type,
        options: question.options ? JSON.stringify(question.options) : null
      }
    }));

    // Update the template
    const updatedTemplate = await prisma.template.update({
      where: { id: Number(templateId) },
      data: {
        title,
        description,
        topic,
        isPublic,
        questions: {
          upsert: questionsUpdate,
          deleteMany: {
            id: { notIn: questions.map(q => q.id).filter(id => id) }
          }
        }
      },
      include: { questions: true }
    });

    res.json(updatedTemplate);
  } catch (error) {
    console.error("Error updating template:", error);
    res.status(500).json({ error: "Failed to update template" });
  }
});


app.delete("/templates/:templateId", verifyToken,verifyAdmin, async (req, res) => {
  const { templateId } = req.params;

  try {
    // First, delete all questions related to this template
    await prisma.question.deleteMany({
      where: { templateId: Number(templateId) },
    });

    // Now, delete the template
    await prisma.template.delete({
      where: { id: Number(templateId) },
    });

    res.json({ message: "Template deleted successfully" });
  } catch (error) {
    console.error("Error deleting template:", error);
    res.status(500).json({ error: "Failed to delete template" });
  }
});
app.get("/tags/search", async (req, res) => {
  const { tag } = req.query;

  if (!tag) {
    return res.status(400).json({ error: "Tag name is required" });
  }

  try {
    const templates = await prisma.template.findMany({
      where: {
        tags: {
          some: {
            name: tag, // Match the tag name
          },
        },
      },
      include: {
        author: {
          select: { username: true },
        },
        tags: {
          select: { name: true },
        },
      },
    });

    res.json(templates);
  } catch (error) {
    console.error("Error fetching templates by tag:", error);
    res.status(500).json({ error: "Failed to fetch templates" });
  }
});
app.get("/forms/template/:templateId", async (req, res) => {
  const { templateId } = req.params;

  try {
    const forms = await prisma.form.findMany({
      where: { templateId: parseInt(templateId) },
      include: {
        user: { select: { username: true } }, // Fetch user's name
        answers: {
          include: {
            question: { select: { title: true } }, // Fetch related question
          },
        },
      },
    });

    if (!forms.length) {
      return res.status(404).json({ message: "No submissions found." });
    }

    res.json(forms);
  } catch (error) {
    console.error("Error fetching forms:", error);
    res.status(500).json({ error: "Failed to fetch forms" });
  }
});

app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});
