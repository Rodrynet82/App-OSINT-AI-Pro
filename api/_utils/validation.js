
export function validateApiKey(key) {
    const validKey = process.env.ANTIGRAVITY_API_KEY || 'ag_pro_live_9k2m8L4n7P0vXy1z';

    if (!key || key.trim() !== validKey.trim()) {
        console.warn(`[AUTH] Validation failed. Received: ${key ? '***' + key.slice(-4) : 'none'}, Expected: ***${validKey.slice(-4)}`);
        return {
            isValid: false,
            error: 'Invalid or missing ANTIGRAVITY_API_KEY',
            creditsRemaining: 0
        };
    }

    // Simulated credit system
    // In a real app, this would query a database
    return {
        isValid: true,
        creditsRemaining: 1500, // Example static credits
        plan: 'Premium Pro'
    };
}

export function handlePreFlight(req, res) {
    const apiKey = req.headers['x-antigravity-key'] || req.query.apiKey;
    const validation = validateApiKey(apiKey);

    if (!validation.isValid) {
        return res.status(401).json({
            success: false,
            ...validation
        });
    }

    return res.status(200).json({
        success: true,
        message: 'Pre-flight check successful',
        ...validation
    });
}
