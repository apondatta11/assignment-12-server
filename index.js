require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();

const admin = require("firebase-admin");

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);
// const jwt=require('jsonwebtoken')
// const cookieParser = require('cookie-parser')
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

app.use(cors());
// app.use(cors({
//     origin: ['client side base url'],
//     credentials: true
// }));
app.use(express.json());
// app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.yp67wht.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
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

// Verify Token Middleware
const verifyToken = async (req, res, next) => {
  if (!req.headers?.authorization) {
    return res.status(401).send({ message: "Unauthorized access" });
  }
  const token = req.headers.authorization.split(" ")[1];
  try {
    const decodedUser = await admin.auth().verifyIdToken(token);
    req.user = decodedUser;
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(401).send({ message: "Unauthorized access" });
  }
};

// Verify Admin Middleware
const verifyAdmin = async (req, res, next) => {
  const email = req.user.email;
  const query = { email: email };
  const user = await usersCollection.findOne(query);
  if (user?.role !== "admin" && user?.role !== "merchant") {
    return res.status(403).send({ message: "Forbidden access" });
  }
  next();
};

async function run() {
  try {
    await client.connect();
    const db = client.db("insuranceDB");

    // Core Collections
    const usersCollection = db.collection("users");
    const policiesCollection = db.collection("policies");
    const applicationsCollection = db.collection("applications");
    const paymentsCollection = db.collection("payments");
    const blogsCollection = db.collection("blogs");
    const reviewsCollection = db.collection("reviews");
    const claimsCollection = db.collection("claims");
    const newsletterCollection = db.collection("newsletter");

    // ==================== POLICIES API ROUTES ====================

    // GET: Get all policies (Public)
    app.get("/policies", async (req, res) => {
      try {
        const { category, search } = req.query;
        let query = { status: "active" };

        if (category && category !== "all") {
          query.category = category;
        }

        if (search) {
          query.title = { $regex: search, $options: "i" };
        }

        const policies = await policiesCollection.find(query).toArray();
        res.send(policies);
      } catch (error) {
        console.error("Error fetching policies:", error);
        res.status(500).send({ message: "Failed to fetch policies" });
      }
    });

    // GET: Get single policy by ID (Public)
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

    // GET: Get popular policies (6 most purchased)
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

    // POST: Create new policy (Admin/Merchant only)
    app.post("/policies", async (req, res) => {
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

    // PUT: Update policy (Admin/Merchant only)
    app.put("/policies/:id", async (req, res) => {
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

    // DELETE: Delete policy (Admin/Merchant only)
    app.delete("/policies/:id", async (req, res) => {
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

    // POST: Submit application (Temporarily without auth)
    app.post("/applications", async (req, res) => {
      try {
        const application = req.body;

        // Validate required fields - ADD annualIncome to required fields
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
        const missingFields = requiredFields.filter(
          (field) => !application[field]
        );

        if (missingFields.length > 0) {
          return res.status(400).send({
            message: `Missing required fields: ${missingFields.join(", ")}`,
          });
        }

        // Verify policy exists and is active
        const policy = await policiesCollection.findOne({
          _id: new ObjectId(application.policyId),
          status: "active",
        });

        if (!policy) {
          return res
            .status(404)
            .send({ message: "Policy not found or inactive" });
        }

        // Check if user already has a pending application for this policy
        const existingApplication = await applicationsCollection.findOne({
          userEmail: application.email,
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
          userEmail: application.email,
          policyId: application.policyId,
          status: "pending",
          appliedAt: new Date(),
          quoteData: application.quoteData || {},
          estimatedPremium: application.estimatedPremium || {},
          // Additional metadata
          policyDetails: {
            title: policy.title,
            category: policy.category,
            coverage: policy.coverage,
            duration: policy.duration,
            premiumDetails: policy.premiumDetails,
          },
        };

        const result = await applicationsCollection.insertOne(applicationData);

        // Update policy popularity
        await policiesCollection.updateOne(
          { _id: new ObjectId(application.policyId) },
          { $inc: { popularity: 1 } }
        );

        res.send({
          message: "Application submitted successfully",
          applicationId: result.insertedId, // Use the MongoDB _id
          application: applicationData,
        });
      } catch (error) {
        console.error("Error submitting application:", error);
        res.status(500).send({ message: "Failed to submit application" });
      }
    });

    // GET: Get user's applications (Protected)
    app.get("/my-applications", async (req, res) => {
      try {
        const userEmail = req.user.email;
        const { status, page = 1, limit = 10 } = req.query;

        let query = { userEmail: userEmail };
        if (status && status !== "all") {
          query.status = status;
        }

        const options = {
          sort: { appliedAt: -1 },
          skip: (parseInt(page) - 1) * parseInt(limit),
          limit: parseInt(limit),
        };

        const applications = await applicationsCollection
          .find(query, options)
          .toArray();
        const total = await applicationsCollection.countDocuments(query);

        // Get policy details for each application
        const applicationsWithDetails = await Promise.all(
          applications.map(async (app) => {
            const policy = await policiesCollection.findOne({
              _id: new ObjectId(app.policyId),
            });
            return {
              ...app,
              policyDetails: policy,
            };
          })
        );

        res.send({
          applications: applicationsWithDetails,
          totalApplications: total,
          currentPage: parseInt(page),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        console.error("Error fetching applications:", error);
        res.status(500).send({ message: "Failed to fetch applications" });
      }
    });

    // GET: Get single application (Protected)
    app.get("/applications/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const userEmail = req.user.email;

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(id),
          userEmail: userEmail,
        });

        if (!application) {
          return res.status(404).send({ message: "Application not found" });
        }

        // Get policy details
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

    // PUT: Update application status (Admin/Merchant only)
    app.put("/applications/:id/status", async (req, res) => {
      try {
        const id = req.params.id;
        const { status, adminNotes } = req.body;

        if (
          !status ||
          !["pending", "approved", "rejected", "under_review"].includes(status)
        ) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!application) {
          return res.status(404).send({ message: "Application not found" });
        }

        const updateData = {
          status: status,
          updatedAt: new Date(),
          reviewedBy: req.user.email,
          reviewedAt: new Date(),
        };

        if (adminNotes) {
          updateData.adminNotes = adminNotes;
        }

        const result = await applicationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        res.send({
          message: `Application ${status} successfully`,
          application: await applicationsCollection.findOne({
            _id: new ObjectId(id),
          }),
        });
      } catch (error) {
        console.error("Error updating application status:", error);
        res
          .status(500)
          .send({ message: "Failed to update application status" });
      }
    });

    // GET: Get all applications (Admin/Merchant only)
    app.get("/applications", async (req, res) => {
      try {
        const { status, page = 1, limit = 10, search } = req.query;

        let query = {};
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

        const options = {
          sort: { appliedAt: -1 },
          skip: (parseInt(page) - 1) * parseInt(limit),
          limit: parseInt(limit),
        };

        const applications = await applicationsCollection
          .find(query, options)
          .toArray();
        const total = await applicationsCollection.countDocuments(query);

        // Get policy details for each application
        const applicationsWithDetails = await Promise.all(
          applications.map(async (app) => {
            const policy = await policiesCollection.findOne({
              _id: new ObjectId(app.policyId),
            });
            const user = await usersCollection.findOne({
              email: app.userEmail,
            });
            return {
              ...app,
              policyDetails: policy,
              userDetails: {
                name: user?.name,
                role: user?.role,
              },
            };
          })
        );

        res.send({
          applications: applicationsWithDetails,
          totalApplications: total,
          currentPage: parseInt(page),
          totalPages: Math.ceil(total / parseInt(limit)),
        });
      } catch (error) {
        console.error("Error fetching applications:", error);
        res.status(500).send({ message: "Failed to fetch applications" });
      }
    });

    // DELETE: Delete application (Protected - user can only delete their own pending applications)
    app.delete("/applications/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const userEmail = req.user.email;

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(id),
          userEmail: userEmail,
        });

        if (!application) {
          return res.status(404).send({ message: "Application not found" });
        }

        if (application.status !== "pending") {
          return res.status(400).send({
            message: "Cannot delete application that is not in pending status",
          });
        }

        const result = await applicationsCollection.deleteOne({
          _id: new ObjectId(id),
          userEmail: userEmail,
        });

        res.send({ message: "Application deleted successfully" });
      } catch (error) {
        console.error("Error deleting application:", error);
        res.status(500).send({ message: "Failed to delete application" });
      }
    });

    // ==================== USER MANAGEMENT ====================

    // Save/Update user in database
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
        const result = await usersCollection.updateOne(
          query,
          updateDoc,
          options
        );
        res.send(result);
      } catch (error) {
        console.error("Error saving user:", error);
        res.status(500).send({ message: "Failed to save user" });
      }
    });

    // GET: Get user role
    app.get("/users/:email", async (req, res) => {
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

    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    //         // Ensures that the client will close when you finish/error
    //         // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Insurance Incoming");
});

app.listen(port, () => {
  console.log(`Insurance Management API listening on port ${port}`);
});
