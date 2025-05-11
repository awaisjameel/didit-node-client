require('dotenv').config();
const { DiDiTClient } = require('didit-node-client');

async function runBasicVerification() {
    const client = new DiDiTClient({
        clientId: process.env.DIDIT_CLIENT_ID,
        clientSecret: process.env.DIDIT_CLIENT_SECRET,
        debug: true,
    });

    try {
        // Create a verification session
        const session = await client.createSession(
            'https://your-app.com/verification/callback',
            '123',
            { features: 'OCR + FACE' }
        );
        console.log('Session created:', session);

        // Get verification result after user completes the process
        const verificationResult = await client.getSession(session.session_id);
        console.log('Verification result:', verificationResult);

        // Example of handling the verification result
        if (verificationResult.kyc?.status === 'Approved' &&
            verificationResult.face?.status === 'Approved') {
            console.log('User verified successfully!');
            console.log('User details:', {
                name: verificationResult.kyc.full_name,
                document: verificationResult.kyc.document_type,
                faceMatchScore: verificationResult.face.face_match_similarity
            });
        }
    } catch (error) {
        console.error('Error:', error.message);
        console.error('Context:', error.context);
    }
}

runBasicVerification();
