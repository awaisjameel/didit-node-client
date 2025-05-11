require('dotenv').config();
const express = require('express');
const { DiDiTClient, createRawBodyMiddleware } = require('didit-node-client');

const app = express();
const port = 3000;

// Initialize DiDiT client
const client = new DiDiTClient({
    clientId: process.env.DIDIT_CLIENT_ID,
    clientSecret: process.env.DIDIT_CLIENT_SECRET,
    webhookSecret: process.env.DIDIT_WEBHOOK_SECRET,
    debug: true,
});

// Parse JSON bodies
app.use(express.json());

// Webhook endpoint with raw body parsing
app.use('/webhook', createRawBodyMiddleware());

// Start verification session
app.post('/verify', async (req, res) => {
    try {
        const { userId, redirectUrl } = req.body;
        if (!userId || !redirectUrl) {
            return res.status(400).json({ error: 'userId and redirectUrl are required' });
        }

        const session = await client.createSession(
            redirectUrl,
            userId,
            { features: 'OCR + FACE' }
        );

        res.json({
            success: true,
            verificationUrl: session.url,
            sessionId: session.session_id
        });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get verification status
app.get('/verify/:sessionId', async (req, res) => {
    try {
        const session = await client.getSession(req.params.sessionId);
        res.json(session);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Webhook handler
app.post('/webhook', async (req, res) => {
    try {
        const webhookData = client.processWebhook(req);
        console.log('Webhook received:', webhookData);

        // Handle verification status
        if (webhookData.status === 'Approved') {
            // Update user status in your database
            console.log('Verification approved for session:', webhookData.session_id);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Download verification report
app.get('/verify/:sessionId/report', async (req, res) => {
    try {
        const pdfBuffer = await client.generateSessionPDF(req.params.sessionId);
        res.type('application/pdf');
        res.send(pdfBuffer);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
