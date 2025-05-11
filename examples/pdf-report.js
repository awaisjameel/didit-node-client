require('dotenv').config();
const fs = require('fs').promises;
const path = require('path');
const { DiDiTClient } = require('didit-node-client');

async function generateAndSaveReport(sessionId) {
    const client = new DiDiTClient({
        clientId: process.env.DIDIT_CLIENT_ID,
        clientSecret: process.env.DIDIT_CLIENT_SECRET,
        debug: true,
    });

    try {
        // Get verification details
        const session = await client.getSession(sessionId);
        console.log('Generating report for session:', session.session_id);

        // Generate PDF report
        const pdfBuffer = await client.generateSessionPDF(sessionId);

        // Create reports directory if it doesn't exist
        const reportsDir = path.join(__dirname, 'reports');
        await fs.mkdir(reportsDir, { recursive: true });

        // Save PDF with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `verification-${sessionId}-${timestamp}.pdf`;
        const filePath = path.join(reportsDir, fileName);

        await fs.writeFile(filePath, pdfBuffer);
        console.log('PDF report saved:', filePath);

        // Optional: Store report metadata
        const metadata = {
            sessionId: session.session_id,
            generatedAt: new Date().toISOString(),
            status: session.status,
            fileName
        };
        await fs.writeFile(
            `${filePath}.json`,
            JSON.stringify(metadata, null, 2)
        );

        return filePath;
    } catch (error) {
        console.error('Error generating report:', error);
        throw error;
    }
}

// Example usage
if (require.main === module) {
    const sessionId = process.argv[2];
    if (!sessionId) {
        console.error('Please provide a session ID');
        process.exit(1);
    }

    generateAndSaveReport(sessionId)
        .then(filePath => console.log('Success! Report saved to:', filePath))
        .catch(error => {
            console.error('Failed to generate report:', error);
            process.exit(1);
        });
}
