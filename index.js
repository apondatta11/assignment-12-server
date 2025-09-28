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
    return res.status(401).send({ message: 'Unauthorized access' });
  }
  const token = req.headers.authorization.split(' ')[1];
  try {
    const decodedUser = await admin.auth().verifyIdToken(token);
    req.user = decodedUser;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).send({ message: 'Unauthorized access' });
  }
};

// Verify Admin Middleware
const verifyAdmin = async (req, res, next) => {
  const email = req.user.email;
  const query = { email: email };
  const user = await usersCollection.findOne(query);
  if (user?.role !== 'admin' && user?.role !== 'merchant') {
    return res.status(403).send({ message: 'Forbidden access' });
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
    app.get('/policies', async (req, res) => {
      try {
        const { category, search } = req.query;
        let query = { status: 'active' };
        
        if (category && category !== 'all') {
          query.category = category;
        }
        
        if (search) {
          query.title = { $regex: search, $options: 'i' };
        }

        const policies = await policiesCollection.find(query).toArray();
        res.send(policies);
      } catch (error) {
        console.error('Error fetching policies:', error);
        res.status(500).send({ message: 'Failed to fetch policies' });
      }
    });

    // GET: Get single policy by ID (Public)
    app.get('/policies/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const policy = await policiesCollection.findOne(query);
        
        if (!policy) {
          return res.status(404).send({ message: 'Policy not found' });
        }
        
        res.send(policy);
      } catch (error) {
        console.error('Error fetching policy:', error);
        res.status(500).send({ message: 'Failed to fetch policy' });
      }
    });

    // GET: Get popular policies (6 most purchased)
    app.get('/popular-policies', async (req, res) => {
      try {
        const policies = await policiesCollection
          .find({ status: 'active' })
          .sort({ popularity: -1 })
          .limit(6)
          .toArray();
        res.send(policies);
      } catch (error) {
        console.error('Error fetching popular policies:', error);
        res.status(500).send({ message: 'Failed to fetch popular policies' });
      }
    });

    // POST: Create new policy (Admin/Merchant only)
    app.post('/policies', async (req, res) => {
      try {
        const policy = req.body;
        policy.createdAt = new Date();
        policy.updatedAt = new Date();
        policy.popularity = 0;
        policy.status = 'active';
        
        const result = await policiesCollection.insertOne(policy);
        res.send(result);
      } catch (error) {
        console.error('Error creating policy:', error);
        res.status(500).send({ message: 'Failed to create policy' });
      }
    });

    // PUT: Update policy (Admin/Merchant only)
    app.put('/policies/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const policy = req.body;
        policy.updatedAt = new Date();
        
        const filter = { _id: new ObjectId(id) };
        const options = { upsert: false };
        const updateDoc = {
          $set: policy
        };
        
        const result = await policiesCollection.updateOne(filter, updateDoc, options);
        res.send(result);
      } catch (error) {
        console.error('Error updating policy:', error);
        res.status(500).send({ message: 'Failed to update policy' });
      }
    });

    // DELETE: Delete policy (Admin/Merchant only)
    app.delete('/policies/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await policiesCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        console.error('Error deleting policy:', error);
        res.status(500).send({ message: 'Failed to delete policy' });
      }
    });

    // ==================== USER MANAGEMENT ====================

    // Save/Update user in database
    app.put('/users/:email', async (req, res) => {
      try {
        const email = req.params.email;
        const user = req.body;
        const query = { email: email };
        const options = { upsert: true };
        const updateDoc = {
          $set: {
            ...user,
            lastLoggedAt: new Date()
          }
        };
        const result = await usersCollection.updateOne(query, updateDoc, options);
        res.send(result);
      } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).send({ message: 'Failed to save user' });
      }
    });

    // GET: Get user role
    app.get('/users/:email', async (req, res) => {
      try {
        const email = req.params.email;
        const query = { email: email };
        const user = await usersCollection.findOne(query);
        res.send({ role: user?.role || 'customer' });
      } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).send({ message: 'Failed to fetch user' });
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
