import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import fs from "fs";
import multer from "multer";
import path from "path";
import admin from "firebase-admin";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";

dotenv.config();
const app = express();

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

import Stripe from "stripe";
const stripe = new Stripe(process.env.PAYMENT_GATEWAY_KEY);
const port = process.env.PORT || 3000;
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";

app.use(
  cors({
    origin: [
      "https://assignment-12-client-d6f9a.web.app",
      "http://localhost:5173",
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use("/uploads", express.static("uploads"));

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.yp67wht.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "insurance-claims",
    format: async (req, file) => {
      const allowedFormats = ["jpeg", "jpg", "png", "pdf"];
      const format = file.mimetype.split("/")[1];
      return allowedFormats.includes(format) ? format : "pdf";
    },
    public_id: (req, file) => {
      return `claim-${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    },
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only PDF, JPEG, JPG, and PNG files are allowed"));
    }
  },
});

// async function run() {
// try {
try {
  await client.connect();
  console.log("Connected to MongoDB");
} catch (err) {
  console.error("Failed to connect to MongoDB", err);
}

// Collections
const db = client.db("insuranceDB");
const usersCollection = db.collection("users");
const policiesCollection = db.collection("policies");
const applicationsCollection = db.collection("applications");
const paymentsCollection = db.collection("payments");
const blogsCollection = db.collection("blogs");
const reviewsCollection = db.collection("reviews");
const claimsCollection = db.collection("claims");
const newsletterCollection = db.collection("newsletter");

const verifyFirebaseToken = async (req, res, next) => {
  try {
    const authHeader = req.headers?.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({ message: "Authentication required" });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).send({ message: "Token not found" });
    }

    // Verify Firebase token
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;

    next();
  } catch (error) {
    console.error("Token verification error:", error);

    if (error.code === "auth/id-token-expired") {
      return res.status(401).send({ message: "Token expired" });
    }

    if (error.code === "auth/id-token-revoked") {
      return res.status(401).send({ message: "Token revoked" });
    }

    return res.status(401).send({ message: "Invalid token" });
  }
};

const getUserRole = async (email) => {
  try {
    const user = await usersCollection.findOne({ email });
    return user?.role || "customer";
  } catch (error) {
    console.error("Error fetching user role:", error);
    return "customer";
  }
};

const verifyAdmin = async (req, res, next) => {
  try {
    await verifyFirebaseToken(req, res, async () => {
      const userEmail = req.user.email;
      const userRole = await getUserRole(userEmail);

      if (userRole !== "admin") {
        return res.status(403).send({ message: "Admin access required" });
      }

      next();
    });
  } catch (error) {
    console.error("Admin verification error:", error);
    return res.status(500).send({ message: "Authorization failed" });
  }
};

const verifyAgent = async (req, res, next) => {
  try {
    await verifyFirebaseToken(req, res, async () => {
      const userEmail = req.user.email;
      const userRole = await getUserRole(userEmail);

      if (userRole !== "agent") {
        return res.status(403).send({ message: "Agent access required" });
      }

      next();
    });
  } catch (error) {
    console.error("Agent verification error:", error);
    return res.status(500).send({ message: "Authorization failed" });
  }
};

const verifyAdminOrAgent = async (req, res, next) => {
  try {
    await verifyFirebaseToken(req, res, async () => {
      const userEmail = req.user.email;
      const userRole = await getUserRole(userEmail);

      if (userRole !== "admin" && userRole !== "agent") {
        return res
          .status(403)
          .send({ message: "Admin or agent access required" });
      }

      next();
    });
  } catch (error) {
    console.error("Admin/Agent verification error:", error);
    return res.status(500).send({ message: "Authorization failed" });
  }
};

const verifyCustomer = async (req, res, next) => {
  try {
    await verifyFirebaseToken(req, res, async () => {
      const userEmail = req.user.email;
      const userRole = await getUserRole(userEmail);

      if (userRole !== "customer") {
        return res.status(403).send({ message: "Customer access required" });
      }

      next();
    });
  } catch (error) {
    console.error("Customer verification error:", error);
    return res.status(500).send({ message: "Authorization failed" });
  }
};

const verifyToken = async (req, res, next) => {
  await verifyFirebaseToken(req, res, next);
};

//Policies APIs

app.get("/policies", async (req, res) => {
  try {
    const { category, search, page = 1, admin = false } = req.query;

    // Set pagination - different for admin vs public
    const policiesPerPage = admin ? 100 : 9; // Admin gets all, public gets paginated
    const skip = admin ? 0 : (page - 1) * policiesPerPage;

    let query = {};

    // Admin can see all policies, public only sees active ones
    if (!admin) {
      query.status = "active";
    }

    // Category filter
    if (category && category !== "all") {
      query.category = category;
    }

    // Search filter - enhanced for both components
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];

      // Additional search fields for admin (ManagePolicies)
      if (admin) {
        query.$or.push(
          { "coverage.minAmount": { $regex: search, $options: "i" } },
          { "coverage.maxAmount": { $regex: search, $options: "i" } }
        );
      }
    }

    // Get total count for pagination
    const totalPolicies = await policiesCollection.countDocuments(query);
    const policies = await policiesCollection
      .find(query)
      .skip(skip)
      .limit(policiesPerPage)
      .toArray();

    // Different response format based on admin flag
    if (admin) {
      // For ManagePolicies - return simple array
      res.send(policies);
    } else {
      // For AllPolicies - return paginated response
      res.send({
        policies,
        totalPages: Math.ceil(totalPolicies / policiesPerPage),
        currentPage: parseInt(page),
        totalPolicies,
      });
    }
  } catch (error) {
    console.error("Error fetching policies:", error);
    res.status(500).send({ message: "Failed to fetch policies" });
  }
});

app.get("/policies/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const policy = await policiesCollection.findOne(query);

    if (!policy) {
      return res.status(404).send({ message: "Policy not found" });
    }

    res.send(policy);
  } catch (error) {
    console.error("Error fetching policy:", error);
    res.status(500).send({ message: "Failed to fetch policy" });
  }
});

app.get("/popular-policies", async (req, res) => {
  try {
    const policies = await policiesCollection
      .find({ status: "active" })
      .sort({ popularity: -1 })
      .limit(6)
      .toArray();
    res.send(policies);
  } catch (error) {
    console.error("Error fetching popular policies:", error);
    res.status(500).send({ message: "Failed to fetch popular policies" });
  }
});

app.post("/policies", verifyAdmin, async (req, res) => {
  try {
    const policy = req.body;
    policy.createdAt = new Date();
    policy.updatedAt = new Date();
    policy.popularity = 0;
    policy.status = "active";

    const result = await policiesCollection.insertOne(policy);
    res.send(result);
  } catch (error) {
    console.error("Error creating policy:", error);
    res.status(500).send({ message: "Failed to create policy" });
  }
});

app.put("/policies/:id", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const policy = req.body;
    policy.updatedAt = new Date();

    const filter = { _id: new ObjectId(id) };
    const options = { upsert: false };
    const updateDoc = {
      $set: policy,
    };

    const result = await policiesCollection.updateOne(
      filter,
      updateDoc,
      options
    );
    res.send(result);
  } catch (error) {
    console.error("Error updating policy:", error);
    res.status(500).send({ message: "Failed to update policy" });
  }
});

app.delete("/policies/:id", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await policiesCollection.deleteOne(query);
    res.send(result);
  } catch (error) {
    console.error("Error deleting policy:", error);
    res.status(500).send({ message: "Failed to delete policy" });
  }
});

//Application APIs
app.post("/applications", verifyToken, async (req, res) => {
  try {
    const application = req.body;
    const userEmail = req.user.email;
    const userRole = await getUserRole(userEmail);

    // Only customers can submit applications
    if (userRole !== "customer") {
      return res
        .status(403)
        .send({ message: "Only customers can submit applications" });
    }

    const requiredFields = [
      "policyId",
      "fullName",
      "email",
      "phone",
      "nidNumber",
      "nomineeName",
      "nomineeRelationship",
      "annualIncome",
    ];
    const missingFields = requiredFields.filter((field) => !application[field]);

    if (missingFields.length > 0) {
      return res.status(400).send({
        message: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }

    // Verify that the email in the application matches the authenticated user
    if (application.email !== userEmail) {
      return res
        .status(403)
        .send({ message: "Application email must match your account email" });
    }

    const policy = await policiesCollection.findOne({
      _id: new ObjectId(application.policyId),
      status: "active",
    });

    if (!policy) {
      return res.status(404).send({ message: "Policy not found or inactive" });
    }

    const existingApplication = await applicationsCollection.findOne({
      userEmail: userEmail,
      policyId: application.policyId,
      status: "pending",
    });

    if (existingApplication) {
      return res.status(400).send({
        message: "You already have a pending application for this policy",
      });
    }

    const applicationData = {
      ...application,
      userEmail: userEmail, // Use authenticated user's email
      policyId: application.policyId,
      status: "pending",
      appliedAt: new Date(),
      quoteData: application.quoteData || {},
      estimatedPremium: application.estimatedPremium || {},
      policyDetails: {
        title: policy.title,
        category: policy.category,
        coverage: policy.coverage,
        duration: policy.duration,
        premiumDetails: policy.premiumDetails,
      },
    };

    const result = await applicationsCollection.insertOne(applicationData);

    await policiesCollection.updateOne(
      { _id: new ObjectId(application.policyId) },
      { $inc: { popularity: 1 } }
    );

    res.send({
      message: "Application submitted successfully",
      application: applicationData,
    });
  } catch (error) {
    console.error("Error submitting application:", error);
    res.status(500).send({ message: "Failed to submit application" });
  }
});

app.get("/applications/:id", verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    const userEmail = req.user.email;
    const userRole = await getUserRole(userEmail);

    let query = { _id: new ObjectId(id) };

    // Customers can only see their own applications
    if (userRole === "customer") {
      query.userEmail = userEmail;
    }
    // Admin and Agent can see any application

    const application = await applicationsCollection.findOne(query);

    if (!application) {
      return res.status(404).send({ message: "Application not found" });
    }

    const policy = await policiesCollection.findOne({
      _id: new ObjectId(application.policyId),
    });

    res.send({
      ...application,
      policyDetails: policy,
    });
  } catch (error) {
    console.error("Error fetching application:", error);
    res.status(500).send({ message: "Failed to fetch application" });
  }
});

app.get("/applications", verifyToken, async (req, res) => {
  try {
    const {
      status,
      page = 1,
      limit = 100,
      search,
      email,
      agentEmail,
    } = req.query;
    const userEmail = req.user.email;
    const userRole = await getUserRole(userEmail);

    console.log("📋 Fetching applications with params:", {
      status,
      email,
      agentEmail,
      userRole,
      userEmail,
    });

    let query = {};

    // Role-based filtering
    if (userRole === "customer") {
      // Customers can only see their own applications
      query.userEmail = userEmail;
    } else if (userRole === "agent") {
      // Agents can see applications assigned to them
      query.assignedAgentEmail = userEmail;
    }
    // Admin can see all applications, no filter needed

    // Additional filtering for specific requests
    if (email && userRole === "admin") {
      // Admin can filter by specific user email
      query.userEmail = email;
    } else if (agentEmail && userRole === "admin") {
      // Admin can filter by specific agent email
      query.assignedAgentEmail = agentEmail;
    }

    // Security check - prevent unauthorized access
    if (email && userRole === "customer" && email !== userEmail) {
      return res
        .status(403)
        .send({ message: "You can only view your own applications" });
    }

    if (agentEmail && userRole === "agent" && agentEmail !== userEmail) {
      return res
        .status(403)
        .send({ message: "You can only view your assigned applications" });
    }

    if (status && status !== "all") {
      query.status = status;
    }

    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
        { applicationId: { $regex: search, $options: "i" } },
      ];
    }

    const applications = await applicationsCollection
      .find(query)
      .sort({ appliedAt: -1 })
      .toArray();

    const total = applications.length;

    const applicationsWithDetails = await Promise.all(
      applications.map(async (app) => {
        const policy = await policiesCollection.findOne({
          _id: new ObjectId(app.policyId),
        });

        // Only add review info for customer queries
        const existingReview =
          userRole === "customer"
            ? await reviewsCollection.findOne({
                userEmail: userEmail,
                policyId: app.policyId,
              })
            : null;

        return {
          ...app,
          policyDetails: policy,
          hasReview: !!existingReview,
        };
      })
    );

    // Return appropriate response format
    if (userRole === "customer") {
      // Customer gets just their applications as array
      res.send(applicationsWithDetails);
    } else if (userRole === "agent") {
      // Agent gets their assigned applications as array
      res.send(applicationsWithDetails);
    } else {
      // Admin gets paginated response
      res.send({
        applications: applicationsWithDetails,
        totalApplications: total,
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
      });
    }
  } catch (error) {
    console.error("Error fetching applications:", error);
    res.status(500).send({ message: "Failed to fetch applications" });
  }
});

app.put("/applications/:id/status", verifyAdminOrAgent, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;
    const userEmail = req.user.email;
    const userRole = await getUserRole(userEmail);

    if (
      !status ||
      !["pending", "approved", "rejected", "under_review"].includes(status)
    ) {
      return res.status(400).send({ message: "Invalid status" });
    }

    let query = { _id: new ObjectId(id) };

    // Agents can only update their assigned applications
    if (userRole === "agent") {
      query.assignedAgentEmail = userEmail;
    }
    // Admin can update any application

    const application = await applicationsCollection.findOne(query);

    if (!application) {
      return res.status(404).send({
        message:
          userRole === "agent"
            ? "Application not found or not assigned to you"
            : "Application not found",
      });
    }

    const updateData = {
      status: status,
      updatedAt: new Date(),
    };

    const result = await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (status === "approved") {
      await policiesCollection.updateOne(
        { _id: new ObjectId(application.policyId) },
        {
          $set: {
            purchaseCount: 0,
            popularity: 0,
          },
        },
        { upsert: true }
      );

      await policiesCollection.updateOne(
        { _id: new ObjectId(application.policyId) },
        {
          $inc: {
            purchaseCount: 1,
            popularity: 1,
          },
        }
      );
      console.log(
        `Increased purchase count for policy: ${application.policyId}`
      );
    }

    const updatedApplication = await applicationsCollection.findOne({
      _id: new ObjectId(id),
    });

    res.send({
      message: `Application ${status} successfully`,
      application: updatedApplication,
    });
  } catch (error) {
    console.error("Error updating application status:", error);
    res.status(500).send({ message: "Failed to update application status" });
  }
});

app.patch("/applications/:id/assign-agent", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { agentId } = req.body;

    const application = await applicationsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!application) {
      return res.status(404).send({ message: "Application not found" });
    }

    const agent = await usersCollection.findOne({
      _id: new ObjectId(agentId),
      role: "agent",
    });

    if (!agent) {
      return res.status(404).send({ message: "Agent not found" });
    }

    const updateData = {
      assignedAgentId: agentId,
      assignedAgentName: agent.name,
      assignedAgentEmail: agent.email,
      updatedAt: new Date(),
      status: "under_review",
    };

    const result = await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "Application not found" });
    }

    res.send({
      message: "Agent assigned successfully",
      application: await applicationsCollection.findOne({
        _id: new ObjectId(id),
      }),
    });
  } catch (error) {
    console.error("Error assigning agent:", error);
    res.status(500).send({ message: "Failed to assign agent" });
  }
});

app.delete("/applications/:id", verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    const userEmail = req.user.email;
    const userRole = await getUserRole(userEmail);

    let query = { _id: new ObjectId(id) };

    // Customers can only delete their own applications
    if (userRole === "customer") {
      query.userEmail = userEmail;
    }
    // Admin can delete any application

    const application = await applicationsCollection.findOne(query);

    if (!application) {
      return res.status(404).send({ message: "Application not found" });
    }

    if (application.status !== "pending" && userRole === "customer") {
      return res.status(400).send({
        message: "Cannot delete application that is not in pending status",
      });
    }

    const result = await applicationsCollection.deleteOne(query);

    res.send({ message: "Application deleted successfully" });
  } catch (error) {
    console.error("Error deleting application:", error);
    res.status(500).send({ message: "Failed to delete application" });
  }
});

//Users APIs
app.get("/users", verifyAdmin, async (req, res) => {
  try {
    const { search, role, page = 1, limit = 10 } = req.query;

    let query = {};

    if (role && role !== "all") {
      query.role = role;
    }
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
      ];
    }

    const options = {
      sort: { createdAt: -1 },
      skip: (parseInt(page) - 1) * parseInt(limit),
      limit: parseInt(limit),
    };

    const users = await usersCollection.find(query, options).toArray();
    const total = await usersCollection.countDocuments(query);

    res.send({
      users,
      totalUsers: total,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send({ message: "Failed to fetch users" });
  }
});

app.get("/users/:email", verifyToken, async (req, res) => {
  try {
    const email = req.params.email;
    const query = { email: email };
    const user = await usersCollection.findOne(query);
    res.send({ role: user?.role || "customer" });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).send({ message: "Failed to fetch user" });
  }
});

app.put("/users/:email", async (req, res) => {
  try {
    const email = req.params.email;
    const user = req.body;
    const query = { email: email };
    const options = { upsert: true };
    const updateDoc = {
      $set: {
        ...user,
        lastLoggedAt: new Date(),
      },
    };
    const result = await usersCollection.updateOne(query, updateDoc, options);
    res.send(result);
  } catch (error) {
    console.error("Error saving user:", error);
    res.status(500).send({ message: "Failed to save user" });
  }
});

app.put("/applications/:id/reject", verifyAdminOrAgent, async (req, res) => {
  try {
    const id = req.params.id;
    const { feedback } = req.body;
    const userEmail = req.user.email;
    const userRole = await getUserRole(userEmail);

    if (!feedback || feedback.trim() === "") {
      return res
        .status(400)
        .send({ message: "Rejection feedback is required" });
    }

    let query = { _id: new ObjectId(id) };

    // Agents can only reject their assigned applications
    if (userRole === "agent") {
      query.assignedAgentEmail = userEmail;
    }
    // Admin can reject any application

    const application = await applicationsCollection.findOne(query);

    if (!application) {
      return res.status(404).send({
        message:
          userRole === "agent"
            ? "Application not found or not assigned to you"
            : "Application not found",
      });
    }

    const updateData = {
      status: "rejected",
      rejectionFeedback: feedback.trim(),
      rejectedBy: userEmail,
      rejectedAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "Application not found" });
    }

    const updatedApplication = await applicationsCollection.findOne({
      _id: new ObjectId(id),
    });

    res.send({
      message: "Application rejected successfully",
      application: updatedApplication,
    });
  } catch (error) {
    console.error("Error rejecting application:", error);
    res.status(500).send({ message: "Failed to reject application" });
  }
});

app.patch("/users/:userId/role", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    if (!["admin", "agent", "customer"].includes(role)) {
      return res.status(400).send({ message: "Invalid role" });
    }

    const result = await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      {
        $set: {
          role: role,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "User not found" });
    }

    res.send({ message: "User role updated successfully" });
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).send({ message: "Failed to update user role" });
  }
});

app.delete("/users/:userId", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await usersCollection.deleteOne({
      _id: new ObjectId(userId),
    });

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: "User not found" });
    }

    res.send({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send({ message: "Failed to delete user" });
  }
});
//Reviews APIs

app.get("/reviews", async (req, res) => {
  try {
    const reviews = await reviewsCollection
      .find({})
      .sort({ createdAt: -1 })
      .limit(5)
      .toArray();

    // Get user data for each review
    const reviewsWithUsers = await Promise.all(
      reviews.map(async (review) => {
        const user = await usersCollection.findOne(
          { email: review.userEmail },
          { projection: { name: 1, photoURL: 1, role: 1 } }
        );

        return {
          ...review,
          user: user || {
            name: review.userEmail?.split("@")[0] || "Customer",
            photoURL: null,
            role: "customer",
          },
        };
      })
    );

    res.send(reviewsWithUsers);
  } catch (error) {
    console.error("Error fetching reviews:", error);
    res.status(500).send({ message: "Failed to fetch reviews" });
  }
});

app.post("/reviews", verifyCustomer, async (req, res) => {
  try {
    // const userEmail = req.user.email;
    const { policyId, rating, feedback, policyName, userEmail } = req.body;

    if (!policyId || !rating || !feedback) {
      return res.status(400).send({ message: "All fields are required" });
    }

    const application = await applicationsCollection.findOne({
      userEmail: userEmail,
      policyId: policyId,
      status: "approved",
    });

    if (!application) {
      return res
        .status(400)
        .send({ message: "You can only review approved policies" });
    }

    const reviewData = {
      userEmail: userEmail,
      policyId: policyId,
      policyName: policyName,
      rating: rating,
      feedback: feedback,
      createdAt: new Date(),
    };

    const result = await reviewsCollection.insertOne(reviewData);
    res.send({
      message: "Review submitted successfully",
      reviewId: result.insertedId,
    });
  } catch (error) {
    console.error("Error submitting review:", error);
    res.status(500).send({ message: "Failed to submit review" });
  }
});

//Payment APIs

app.post("/create-payment-intent", async (req, res) => {
  try {
    const { amount, applicationId, userEmail } = req.body;

    console.log(
      "💳 Creating payment intent for:",
      userEmail,
      "Amount:",
      amount
    );

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency: "usd",
      payment_method_types: ["card"],
      metadata: {
        applicationId: applicationId,
        userEmail: userEmail,
      },
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error("Error creating payment intent:", error);
    res.status(500).send({ message: "Failed to create payment intent" });
  }
});

app.post("/payments", async (req, res) => {
  try {
    const { applicationId, userEmail, amount, transactionId } = req.body;

    // 1. Update application payment status
    const updateResult = await applicationsCollection.updateOne(
      { _id: new ObjectId(applicationId) },
      {
        $set: {
          paymentStatus: "paid", // Add this field
          lastPaymentDate: new Date(),
          nextDueDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(404).send({ message: "Application not found" });
    }

    // 2. Insert payment record
    const paymentData = {
      applicationId,
      userEmail,
      amount,
      transactionId,
      paymentDate: new Date(),
      status: "completed",
    };

    const paymentResult = await paymentsCollection.insertOne(paymentData);

    res.send({
      message: "Payment recorded successfully",
      paymentId: paymentResult.insertedId,
    });
  } catch (error) {
    console.error("Payment processing failed:", error);
    res.status(500).send({ message: "Failed to record payment" });
  }
});

app.get("/payments", verifyToken, async (req, res) => {
  try {
    const { applicationId, userEmail } = req.query;
    let query = {};

    if (applicationId) {
      query.applicationId = applicationId;
    }

    if (userEmail) {
      query.userEmail = userEmail;
    }

    const payments = await paymentsCollection.find(query).toArray();
    res.send(payments);
  } catch (error) {
    console.error("Error fetching payments:", error);
    res.status(500).send({ message: "Failed to fetch payments" });
  }
});

//Claims APIs

app.post("/claims",verifyCustomer,upload.single("document"),async (req, res) => {
    try {
      const { applicationId, policyName, reason } = req.body;
      const userEmail = req.user.email;
      const documentFile = req.file;

      console.log(
        "Submitting claim for:",
        userEmail,
        "Application:",
        applicationId
      );
      if (!applicationId || !policyName || !reason || !userEmail) {
        if (documentFile) {
          fs.unlinkSync(documentFile.path);
        }
        return res.status(400).send({ message: "All fields are required" });
      }

      if (!documentFile) {
        return res.status(400).send({ message: "Document file is required" });
      }

      console.log("Uploaded file:", documentFile);
      const existingClaim = await claimsCollection.findOne({
        applicationId: applicationId,
        userEmail: userEmail,
      });

      if (existingClaim) {
        fs.unlinkSync(documentFile.path);
        return res
          .status(400)
          .send({ message: "Claim already submitted for this policy" });
      }
      const claimData = {
        applicationId,
        policyName,
        reason,
        documentUrl: documentFile.path,
        originalFileName: documentFile.originalname,
        fileSize: documentFile.size,
        fileType: documentFile.mimetype,
        userEmail,
        status: "pending",
        submittedAt: new Date(),
      };

      console.log("Creating new claim:", claimData);

      const result = await claimsCollection.insertOne(claimData);

      res.send({
        message: "Claim submitted successfully",
        claimId: result.insertedId,
        claim: claimData,
      });
    } catch (error) {
      console.error("Error submitting claim:", error);

      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (unlinkError) {
          console.error("Error deleting file:", unlinkError);
        }
      }

      res.status(500).send({
        message: "Failed to submit claim",
        error: error.message,
      });
    }
  }
);

app.get("/claims", verifyToken, async (req, res) => {
  try {
    const userEmail = req.query.email;

    console.log(
      "Fetching claims:",
      userEmail ? `for user ${userEmail}` : "all claims"
    );

    let query = {};
    if (userEmail) {
      query.userEmail = userEmail;
    }

    const claims = await claimsCollection
      .find(query)
      .sort({ submittedAt: -1 })
      .toArray();

    console.log("Found claims:", claims.length);

    res.send(claims);
  } catch (error) {
    console.error("Error fetching claims:", error);
    res.status(500).send({
      message: "Failed to fetch claims",
      error: error.message,
    });
  }
});

app.patch("/claims/:claimId/approve", verifyAgent, async (req, res) => {
  try {
    const { claimId } = req.params;

    console.log("Approving claim:", claimId);

    const result = await claimsCollection.updateOne(
      { _id: new ObjectId(claimId) },
      {
        $set: {
          status: "approved",
          approvedAt: new Date(),
          approvedBy: req.user?.email || "agent",
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "Claim not found" });
    }

    console.log("Claim approved successfully");

    res.send({
      message: "Claim approved successfully",
      claimId: claimId,
    });
  } catch (error) {
    console.error("Error approving claim:", error);
    res.status(500).send({
      message: "Failed to approve claim",
      error: error.message,
    });
  }
});

//Blogs APIs
app.post("/blogs", verifyAdminOrAgent, async (req, res) => {
  try {
    const { title, content, author, category } = req.body;
    console.log("📝 POST /blogs - Data:", {
      title,
      content,
      author,
      category,
    });

    if (!title || !content || !author) {
      return res
        .status(400)
        .send({ message: "Title, content, and author are required" });
    }

    const blogData = {
      title,
      content,
      author,
      category: category || "insurance-tips",
      publishDate: new Date(),
      totalVisits: 0,
      status: "published",
    };

    console.log("Saving blog to database:", blogData);
    const result = await blogsCollection.insertOne(blogData);
    console.log("Blog saved with ID:", result.insertedId);

    res.send({
      message: "Blog published successfully",
      blogId: result.insertedId,
      blog: blogData,
    });
  } catch (error) {
    console.error("Error creating blog:", error);
    res.status(500).send({
      message: "Failed to publish blog",
      error: error.message,
    });
  }
});

app.get("/blogs", async (req, res) => {
  try {
    const { author } = req.query;
    console.log("GET /blogs - Author query:", author);

    let query = {};
    // let query = { status: "published" };// was used in updated form cc
    if (author) {
      query.author = author;
    }

    const blogs = await blogsCollection
      .find(query)
      .sort({ publishDate: -1 })
      .toArray();

    console.log("Found blogs:", blogs.length);
    res.send(blogs);
  } catch (error) {
    console.error("  Error fetching blogs:", error);
    res.status(500).send({
      message: "Failed to fetch blogs",
      error: error.message,
    });
  }
});
app.get("/blogs/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { incrementVisit } = req.query;

    console.log("GET /blogs/:id - ID:", id, "incrementVisit:", incrementVisit);

    if (incrementVisit === "true") {
      await blogsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $inc: { totalVisits: 1 },
          $set: { lastViewed: new Date() },
        }
      );
      console.log("Visit count incremented for blog:", id);
    }

    const blog = await blogsCollection.findOne({ _id: new ObjectId(id) });

    if (!blog) {
      return res.status(404).send({ message: "Blog not found" });
    }

    console.log("Blog found:", blog.title);
    res.send(blog);
  } catch (error) {
    console.error("Error fetching blog:", error);
    res.status(500).send({
      message: "Failed to fetch blog",
      error: error.message,
    });
  }
});

app.patch("/blogs/:id", verifyAdminOrAgent, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, category } = req.body;

    const result = await blogsCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          title,
          content,
          category,
          lastUpdated: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "Blog not found" });
    }

    res.send({
      message: "Blog updated successfully",
      blogId: id,
    });
  } catch (error) {
    console.error("Error updating blog:", error);
    res.status(500).send({
      message: "Failed to update blog",
      error: error.message,
    });
  }
});

app.delete("/blogs/:id", verifyAdminOrAgent, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await blogsCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: "Blog not found" });
    }

    res.send({
      message: "Blog deleted successfully",
      blogId: id,
    });
  } catch (error) {
    console.error("Error deleting blog:", error);
    res.status(500).send({
      message: "Failed to delete blog",
      error: error.message,
    });
  }
});

// Newsletter APIs

app.post("/newsletter", async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!name || !email) {
      return res.status(400).send({ message: "Name and email are required" });
    }

    const existingSubscription = await newsletterCollection.findOne({
      email,
    });
    if (existingSubscription) {
      return res.status(400).send({ message: "Email already subscribed" });
    }

    const subscriptionData = {
      name,
      email,
      subscribedAt: new Date(),
      status: "active",
    };

    const result = await newsletterCollection.insertOne(subscriptionData);
    res.send({
      message: "Successfully subscribed to newsletter",
      subscriptionId: result.insertedId,
    });
  } catch (error) {
    console.error("Error subscribing to newsletter:", error);
    res.status(500).send({ message: "Failed to subscribe" });
  }
});

// Featured Agents API for homepage

app.get("/agents", async (req, res) => {
  try {
    const agents = await usersCollection
      .find({
        role: "agent",
      })
      .limit(3)
      .toArray();
    res.send(agents);
  } catch (error) {
    console.error("Error fetching agents:", error);
    res.status(500).send({ message: "Failed to fetch agents" });
  }
});

//newsletter apis
app.post("/newsletter", async (req, res) => {
  try {
    const { name, email } = req.body;

    console.log(" POST /newsletter - Data:", { name, email });

    if (!name || !email) {
      return res.status(400).send({ message: "Name and email are required" });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res
        .status(400)
        .send({ message: "Please provide a valid email address" });
    }

    // Check if already subscribed
    const existingSubscription = await newsletterCollection.findOne({
      email,
    });
    if (existingSubscription) {
      return res.status(400).send({
        message: "This email is already subscribed to our newsletter",
      });
    }

    const subscriptionData = {
      name: name.trim(),
      email: email.trim(),
      subscribedAt: new Date(),
      status: "active",
    };

    console.log("💾 Saving newsletter subscription:", subscriptionData);
    const result = await newsletterCollection.insertOne(subscriptionData);

    res.send({
      message: "Successfully subscribed to newsletter!",
      subscriptionId: result.insertedId,
      subscription: subscriptionData,
    });
  } catch (error) {
    console.error("❌ Error subscribing to newsletter:", error);
    res.status(500).send({
      message: "Failed to subscribe to newsletter",
      error: error.message,
    });
  }
});

// Connect the client to the server	(optional starting in v4.7)
// await client.connect();
// Send a ping to confirm a successful connection
// await client.db("admin").command({ ping: 1 });
console.log("Pinged your deployment. You successfully connected to MongoDB!");
// }
// finally {
// Ensures that the client will close when you finish/error
// await client.close();
// }
// }
// run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Insurance Incoming");
});

app.get("/apon", (req, res) => {
  res.send("API is running");
});

app.listen(port, () => {
  console.log(`Insurance Management API listening on port ${port}`);
});
