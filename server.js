
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

// Cargar variables de entorno
dotenv.config({ path: '.env.local' });
dotenv.config(); // Fallback a .env si existe

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());

// Servir archivos estáticos del frontend
app.use(express.static('public'));

/**
 * Emulador de Vercel Serverless Functions
 * Mapea automáticamente las rutas /api/* a los archivos en /api/*.js
 */
app.all('/api/:route', async (req, res) => {
    const { route } = req.params;
    const apiFilePath = path.join(__dirname, 'api', `${route}.js`);

    if (fs.existsSync(apiFilePath)) {
        try {
            // Convertir backslashes a forward slashes para que import() funcione correctamente en Windows
            const fileUrl = `file://${apiFilePath.replace(/\\/g, '/')}`;
            const { default: handler } = await import(fileUrl);

            if (typeof handler === 'function') {
                return await handler(req, res);
            } else {
                throw new Error(`El archivo /api/${route}.js no exporta un handler válido.`);
            }
        } catch (error) {
            console.error(`Error en API (${route}):`, error);
            res.status(500).json({
                error: 'Internal Server Error',
                message: error.message,
                details: 'Error ejecutando la función serverless localmente.'
            });
        }
    } else {
        res.status(404).json({ error: 'API route not found' });
    }
});

// Ruta de información del servidor
app.get('/server-status', (req, res) => {
    res.json({
        status: 'online',
        emulation: 'Vercel Serverless Functions',
        port: PORT,
        env: process.env.NODE_ENV || 'development'
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`\x1b[36m%s\x1b[0m`, `---------------------------------------------------`);
    console.log(`\x1b[32m%s\x1b[0m`, `🚀 OSINT AI Pro: Servidor de Desarrollo Iniciado`);
    console.log(`\x1b[32m%s\x1b[0m`, `🌐 Local:   http://localhost:${PORT}`);
    console.log(`\x1b[36m%s\x1b[0m`, `---------------------------------------------------`);
    console.log(`\x1b[33m%s\x1b[0m`, `Emulando funciones de Vercel desde el directorio /api`);
});
