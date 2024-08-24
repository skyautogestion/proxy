// initializing installed dependencies
require('winston-daily-rotate-file');
require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');
const { Pool } = require('pg');
const axios = require('axios');
axios.defaults.timeout = 60000 * 2; // Set default timeout to x minutes
const app = express();
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const env = process.env.NODE_ENV;

const transport = new winston.transports.DailyRotateFile({
  level: 'info',
  filename: 'logs/application-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: false,
  maxSize: '100m',
});

const logger = winston.createLogger({
  transports: [new winston.transports.Console(), transport],
});

const limiter = rateLimit({
  windowMs: 0.5 * 60 * 1000, // 30 seconds
  max: 100, // limit each IP to 5 requests per windowMs
  keyGenerator: (req, res) => {
    const id = uuidv4()
    req.headers['debug-id'] = id
    return req.ip.replace(/:\d+[^:]*$/, '') // IP address from requestIp.mw(), as opposed to req.ip
  },
  message: async (req, res) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || null
    const error = { code: '429', cause: 'RATE-LIMIT IP ' + ip }
    consoleError(error, req, req.headers['debug-id'])
    return res.status(429).json({
      error:
        'Haz superado el número de intentos, por favor intenta en unos minutos.',
    })
  },
});

const preRegistroLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 10, // limit each IP to 10 requests per windowMs
  keyGenerator: (req, res) => {
    const id = uuidv4()
    req.headers['debug-id'] = id
    return req.ip.replace(/:\d+[^:]*$/, '') // IP address from requestIp.mw(), as opposed to req.ip
  },
  message: async (req, res) => {
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    const error = { code: '429', cause: 'RATE-LIMIT IP ' + ip }
    consoleError(error, req, req.headers['debug-id'])
    const errorResponse = {
      EBMHeaderResponse: {
        ErrorTecnico: {
          code: 'ok',
          summary: null,
          detail: null,
          Sistema: 'PreRegistroSelEBF',
        },
        ErrorNegocio: {
          Estado: 'ko',
          CodigoError: '100',
          DescripcionError:
            'Haz superado el número de intentos, por favor intenta en unos minutos.',
        },
      },
    }
    return res.status(429).json(errorResponse)
  },
});

const allowedOrigins = [
  'https://qamiespaciosky.sky.com.mx',
  'https://miespaciosky.sky.com.mx',
  'https://misky.sky.com.mx',
];
if ('development' === env) {
  // local development purposes
  allowedOrigins.push('https://localhost:3000');
}

// X-Rate-Limiting
// set it to 1 if there is nothing behind it (reverse-proxy, WAF, etc)
// if WAF is active set it to 2
app.set('trust proxy', 2);
//app.use(limiter);

// CORS
app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
    preflightContinue: false,
    methods: ['POST', 'GET', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Acceptcrc', 'acceptcrc'],
  }),
);

// HSTS
app.use(helmet());
app.use(
  helmet.hsts({
    maxAge: 300,
    includeSubDomains: true,
    preload: true,
  }),
);

app.use(express.json());

const {
  REACT_APP_URL_INTERNO,
  REACT_APP_USER_INTERNO,
  REACT_APP_PASSWORD_INTERNO,
  REACT_APP_GOOGLE_API_KEY,
  REACT_APP_RECAPTCHA_KEY,
  DATABASE_USERNAME,
  DATABASE_PASSWORD,
  DATABASE_HOST,
  DATABASE_PORT,
  DATABASE_NAME,
} = process.env;

const CONTENT_ACCEPT_JSON = {
  'Content-type': 'application/json',
  Accept: 'application/json',
}

const OSB_AUTH = {
  username: REACT_APP_USER_INTERNO ?? '',
  password: REACT_APP_PASSWORD_INTERNO ?? '',
}

const INTERNO_AUTH = {
  username: REACT_APP_USER_INTERNO ?? '',
  password: REACT_APP_PASSWORD_INTERNO ?? '',
}

const pool = new Pool({
  user: DATABASE_USERNAME,
  password: DATABASE_PASSWORD,
  host: DATABASE_HOST,
  port: DATABASE_PORT,
  database: DATABASE_NAME,
});

// listening for port
app.listen(process.env.PORT, '0.0.0.0', () => 
  logger.log('info', `App listening on port ${process.env.PORT}!`),
);

app.get('/', limiter, (req, res) => {
  const id = uuidv4()
  res.set('debug-id', id)
  const ip =
    req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
  consoleRequestStart(req, id, ip)
  res.json({ message: 'Welcome !!!!' })
});

// Handle errors using the logger
app.use((err, req, res, next) => {
  // Log the error message at the error level
  logger.error("UNHANDLED_EXCEPTION")
  logger.error(err.message);
  res.status(500).send();
});

// API request
app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Solicitud/generarQueja',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/Solicitud/generarQueja',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Solicitud/crearSugerencia',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/Solicitud/crearSugerencia',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Solicitud/responderEncuesta',
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/Solicitud/responderEncuesta',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/AltaSolicitudDeServicioRest',
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/AltaSolicitudDeServicioRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseFlows/Sel/AutenticarUsuarioRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    res.set('debug-id', id)
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url: REACT_APP_URL_INTERNO + '/EnterpriseFlows/Sel/AutenticarUsuarioRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)

        const data = response.data

        if (
          data &&
          data.EBMHeaderResponse?.ErrorTecnico?.code === 'ok' &&
          data.EBMHeaderResponse?.ErrorNegocio?.Estado === 'ok' &&
          data.EBMHeaderResponse?.ErrorNegocio?.CodigoError === '0'
        ) {
          const sessionId = generateSessionId()
          const user = data.ListUsuariosSel?.UsuarioSelEBO?.[0]?.NumeroCuenta
          res.set('X-MY-SKY-SESSION-ID', sessionId)
          saveSessionIdWithUser(sessionId, user).then(res.json(data))
        }
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaConsumoDatosRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaConsumoDatosRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaDatosGeneralesRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaDatosGeneralesRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaPaqAdicionalDatosRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaPaqAdicionalDatosRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaParrillaGuiaSkyRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaParrillaGuiaSkyRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/GestionarSSComprarServiciosRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/GestionarSSComprarServiciosRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseFlows/Sel/ModificarPasswordRegistroRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseFlows/Sel/ModificarPasswordRegistroRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ReEnviarEmailPreRegSelEBSRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ReEnviarEmailPreRegSelEBSRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaPagosPorEventoRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaPagosPorEventoRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaPrecioRecargaRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaPrecioRecargaRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarCuentaAsociada',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Siebel/Cuenta/consultarCuentaAsociada',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

/*
 * se deshabilita temporalmente debido a los ataques
app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarCuentaEspecial", limiter, (req, res) => {
  const id = uuidv4();
  res.set('debug-id', id);
  const ip = req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null;
  consoleRequestStart(req, id, ip);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Cuenta/consultarCuentaEspecial",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      consoleSucess(response, id, ip);
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id, ip);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});
*/

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Cuenta/consultarDatosUsuario',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/Cuenta/consultarDatosUsuario',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    const userHeader = req.headers['X-MY-SKY-ACCOUNT-NUMBER'] || '';
    const userPayload = req.body?.accountNumber || '';
    const sessionId = req.headers['X-MY-SKY-SESSION-ID'] || '';
    const isValidSession = isValidSessionId(sessionId, userHeader, userPayload)

    if(!isValidSession) {
      logger.error('sesión invalida cuenta: '+userHeader, { _id: id, _timestamp: getCurrentDate(), _ip: ip },)
      return res.status(401).json({ msg: 'Unauthorized user' });
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Brm/Factura/consultarEstadoCuenta',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Brm/Factura/consultarEstadoCuenta',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Brm/Factura/consultarFactura',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Brm/Factura/consultarFactura',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Brm/Factura/consultarFacturaPeriodo',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Brm/Factura/consultarFacturaPeriodo',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Cuenta/consultarLDAP',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseServices/Sel/Cuenta/consultarLDAP',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/Pago/consultarPago',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseServices/Siebel/Pago/consultarPago',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/PagoEvento/consultarProducto',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Siebel/PagoEvento/consultarProducto',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarRegimenFiscalRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarRegimenFiscalRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarServiciosAdicionalesRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarServiciosAdicionalesRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarUsoCFDIRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseServices/Sel/ConsultarUsoCFDIRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaSolicitudDeServicioRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaSolicitudDeServicioRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Solicitud/crearSolicitud',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/Solicitud/crearSolicitud',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/EjecutarRemoteBookingRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/EjecutarRemoteBookingRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/RegistrarDatosFiscalesRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/RegistrarDatosFiscalesRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Brm/Factura/obtenerFactura',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Brm/Factura/obtenerFactura',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Okta/Usuario/restablecerContrasena',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Okta/Usuario/restablecerContrasena',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)


app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaCuentaRest',
  limiter,
  (req, res) => {
    const id = uuidv4();
    res.set('debug-id', id);
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null;
    consoleRequestStart(req, id, ip);
    const options = {
      method: 'POST',
      url: REACT_APP_URL_INTERNO + '/EnterpriseServices/Sel/ConsultaCuentaRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    };

    const userHeader = req.headers['X-MY-SKY-ACCOUNT-NUMBER'] || '';
    const userPayload = req.body?.accountNumber || '';
    const sessionId = req.headers['X-MY-SKY-SESSION-ID'] || '';
    const isValidSession = isValidSessionId(sessionId, userHeader, userPayload);

    if(!isValidSession) {
      logger.error('sesión invalida cuenta: '+userHeader, { _id: id, _timestamp: getCurrentDate(), _ip: ip },)
      return res.status(401).json({ msg: 'Unauthorized user' });
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip);
        res.json(response.data);
      })
      .catch(function (error) {
        consoleError(error, req, id, ip);
        return res.status(500).json({ error: 'ocurrio un error inesperado' });
      })
  },
)

app.post(
  '/mi-sky-api/SbConsultaHorariosPagoPorEventoSelEBS/ConsultaHorariosPagoPorEventoRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/SbConsultaHorariosPagoPorEventoSelEBS/ConsultaHorariosPagoPorEventoRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ActivacionBlueToGoRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ActivacionBlueToGoRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ActualizaDatosFiscalesEBFRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ActualizaDatosFiscalesEBFRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaCanalGuiaSkyRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaCanalGuiaSkyRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaControlRemotoRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaControlRemotoRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarDatosFiscalesRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarDatosFiscalesRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarEstadosDeCuentaRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarEstadosDeCuentaRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarFacturaCorporativo',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Siebel/Cuenta/consultarFacturaCorporativo',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/PagoEvento/consultarPPV',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/PagoEvento/consultarPPV',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarSaldosCorrientesRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarSaldosCorrientesRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarServiciosCuentaRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarServiciosCuentaRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/Equipo/consultarTICorporativo',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Siebel/Equipo/consultarTICorporativo',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Solicitud/enviarEmail',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseServices/Sel/Solicitud/enviarEmail',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/GestionarSSComprarDatosRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/GestionarSSComprarDatosRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Okta/Usuario/cambiarContrasena',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Okta/Usuario/cambiarContrasena',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseFlows/Sel/RecuperarPasswordUsrRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseFlows/Sel/RecuperarPasswordUsrRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseFlows/Sel/PreRegistroRest',
  preRegistroLimiter,
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)

    // validate token
    const token = req.headers?.acceptcrc

    const validateTokenData = {
      event: {
        token: token,
        expectedAction: 'USER_ACTION',
        siteKey: REACT_APP_RECAPTCHA_KEY,
      },
    }

    const validateTokenOptions = {
      method: 'POST',
      url:
        'https://recaptchaenterprise.googleapis.com/v1/projects/sel-sky/assessments?key=' +
        REACT_APP_GOOGLE_API_KEY,
      data: validateTokenData,
      headers: {
        'Content-type': 'application/json',
        Accept: 'application/json',
      },
    }

    if (!token) {
      const date = new Date(Date.now()).toLocaleString()
      logger.error('NON_TOKEN_FOUND from IP: ' + ip, {
        _id: id,
        _timestamp: getCurrentDate(),
        _ip: ip,
      })
      return res.status(401).json({ msg: 'Unauthorized user' })
    }

    axios
      .request(validateTokenOptions)
      .then(function (response) {
        const data = response.data
        const reason = data['tokenProperties'].invalidReason
        if (!data['tokenProperties'].valid && reason !== 'DUPE') {
          const date = new Date(Date.now()).toLocaleString()
          logger.error(
            'INVALID_CAPTCHA from IP: ' + ip + ' | reason: ' + reason,
            { id: id },
          )
          return res.status(401).json({ msg: 'Unauthorized user' })
        } else {
          // call OSB
          logger.info('captcha exitoso, se continua al llamado del osb', {
            _id: id,
            _timestamp: getCurrentDate(),
            _ip: ip,
          })
          const options = {
            method: 'POST',
            url: REACT_APP_URL_INTERNO + '/EnterpriseFlows/Sel/PreRegistroRest',
            data: req.body,
            headers: CONTENT_ACCEPT_JSON,
            auth: INTERNO_AUTH,
          }

          axios
            .request(options)
            .then(function (response) {
              consoleSucess(response, id, ip)
              res.json(response.data)
            })
            .catch(function (error) {
              consoleError(error, req, id, ip)
              return res
                .status(500)
                .json({ error: 'ocurrio un error inesperado' })
            })
        }
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(401).json({ msg: 'Unauthorized user' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseFlows/Sel/RegistrarQuejaRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url: REACT_APP_URL_INTERNO + '/EnterpriseFlows/Sel/RegistrarQuejaRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseFlows/Sel/RegistrarSugerenciaRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseFlows/Sel/RegistrarSugerenciaRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/Equipo/consultarIRD',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Siebel/Equipo/consultarIRD',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ValidarPreRegistroRest',
  preRegistroLimiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ValidarPreRegistroRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/PagoEvento/consultarPrecio',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Siebel/PagoEvento/consultarPrecio',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarInformacionFiscalRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarInformacionFiscalRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultarCambioPaquetePrincipalRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultarCambioPaquetePrincipalRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaPaqueteRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseServices/Sel/ConsultaPaqueteRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaVeTVPricesRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaVeTVPricesRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarDireccion',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Siebel/Cuenta/consultarDireccion',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/ConsultaRevistaSKYRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/ConsultaRevistaSKYRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/PagoEvento/consultarCanal',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO +
        '/EnterpriseServices/Sel/PagoEvento/consultarCanal',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/Sel/Sesion/consultarMenu',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url:
        REACT_APP_URL_INTERNO + '/EnterpriseServices/Sel/Sesion/consultarMenu',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseServices/RN/GeneraURLChatRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url: REACT_APP_URL_INTERNO + '/EnterpriseServices/RN/GeneraURLChatRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

app.post(
  '/mi-sky-api/EnterpriseFlows/Sel/CrearRegistroRest',
  limiter,
  (req, res) => {
    const id = uuidv4()
    res.set('debug-id', id)
    const ip =
      req.ip.replace(/:\d+[^:]*$/, '') || req.headers['x-forwarded-for'] || null
    consoleRequestStart(req, id, ip)
    const options = {
      method: 'POST',
      url: REACT_APP_URL_INTERNO + '/EnterpriseFlows/Sel/CrearRegistroRest',
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: INTERNO_AUTH,
    }

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id, ip)
        res.json(response.data)
      })
      .catch(function (error) {
        consoleError(error, req, id, ip)
        return res.status(500).json({ error: 'ocurrio un error inesperado' })
      })
  },
)

function consoleError(error, requestData, id, ip) {
  const errorData = error.response?.data?.error ?? error.message ?? error
  const errorCode = error.code
  const errorCause = error.cause
  const errorUrl = error.config?.url
  const errorMethod = error.config?.method
  const body = requestData.body
  if (body && body.AutenticarUsuarioInputMessage?.Password) {
    body.AutenticarUsuarioInputMessage.Password = 'ENCRYPTED_AND_OMMITED'
  }

  logger.error(
    'code: ' +
      errorCode +
      ' | ' +
      'error: ' +
      JSON.stringify(errorData) +
      ' | ' +
      'cause: ' +
      JSON.stringify(errorCause) +
      ' | ' +
      'url: ' +
      errorUrl +
      ' | ' +
      'method: ' +
      errorMethod +
      ' | ' +
      'requestData: ' +
      JSON.stringify(body, null, 2),
    { _id: id, _timestamp: getCurrentDate(), _ip: ip },
  )
}

function consoleRequestStart(req, id, ip) {
  logger.info(
    ' | url: ' +
      req.path +
      ' | method: ' +
      req.method +
      ' | Request received: ' +
      JSON.stringify(req.body),
    { _id: id, _timestamp: getCurrentDate(), _ip: ip },
  )
}

function consoleSucess(response, id, ip) {
  logger.info(
    'status: ' +
      (response.statusCode || response.status) +
      ' | ' +
      'url: ' +
      (response.request?.uri?.href || response.config?.url) +
      ' | ' +
      'response: ' +
      (JSON.stringify(response.body) || JSON.stringify(response.data)),
    { _id: id, _timestamp: getCurrentDate(), _ip: ip },
  )
}

function getCurrentDate() {
  return new Date(Date.now()).toLocaleString()
}

function generateSessionId() {
  const sessionId = crypto.randomBytes(60).toString('hex')
  return sessionId
}

async function saveSessionIdWithUser(sessionId, user) {
  const searchQuery = "SELECT token_id FROM token_session_my_sky WHERE account_number = $1;"
  const resultSearchToken = await pool.query(searchQuery, [user])
  if(resultSearchToken && resultSearchToken.rows?.length > 0) {
    const query = 'UPDATE token_session_my_sky SET token_id = $1 WHERE account_number = $2;';
    const values = [sessionId, user]
    await pool.query(query, values)
  } else {
    const query = 'INSERT INTO token_session_my_sky(token_id, account_number) VALUES ($1, $2);';
    const values = [sessionId, user]
    await pool.query(query, values)
  }
}

async function isValidSessionId(sessionId, userHeader, userPayload) {
  /*
  if(userHeader !== userPayload) 
    return false;
  */
  const searchQuery = "SELECT token_id FROM token_session_my_sky WHERE account_number = $1 AND token_id = $2;"
  const resultSearchToken = await pool.query(searchQuery, [user, sessionId])
  return resultSearchToken && resultSearchToken.rows?.length > 0;
}


