require('dotenv').config();
const express = require('express');
const { DiDiTClient, createRawBodyMiddleware } = require('didit-node-client');

const app = express();
const port = 3000;

const client = new DiDiTClient({
    webhookSecret: process.env.DIDIT_WEBHOOK_SECRET,
    debug: true,
});

// Add raw body middleware for webhook processing
app.use('/webhook', createRawBodyMiddleware());

app.post('/webhook', async (req, res) => {
    try {
        const webhookData = client.processWebhook(req);
        console.log('Webhook received:', webhookData);

        switch (webhookData.status) {
            case 'Approved':
                // Handle approved verification
                if (webhookData.decision?.kyc?.status === 'Approved') {
                    await updateUserVerificationStatus(webhookData.session_id, 'approved');
                }
                break;

            case 'Declined':
                // Handle declined verification
                await notifyComplianceTeam(webhookData);
                break;

            case 'In Review':
                // Handle manual review required
                await createManualReviewTask(webhookData);
                break;
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Example helper functions
async function updateUserVerificationStatus(sessionId, status) {
    console.log(`Updating user verification status: ${sessionId} -> ${status}`);
}

async function notifyComplianceTeam(webhookData) {
    console.log('Notifying compliance team about declined verification:', webhookData.session_id);
}

async function createManualReviewTask(webhookData) {
    console.log('Creating manual review task for session:', webhookData.session_id);
}

app.listen(port, () => {
    console.log(`Webhook server listening at http://localhost:${port}`);
});
