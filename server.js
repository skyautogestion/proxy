// initializing installed dependencies
const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const winston = require("winston");
require('winston-daily-rotate-file');
require("dotenv").config();
const axios = require("axios");
axios.defaults.timeout = 60000; // Set default timeout to 60 seconds
const app = express();
const cors = require("cors");
const { v4: uuidv4 } = require('uuid');
const env = process.env.NODE_ENV;

const transport = new winston.transports.DailyRotateFile({
  level: 'info',
  filename: 'logs/application-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: false,
  maxSize: '20m',
});

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    transport
  ]
});

const limiter = rateLimit({
  windowMs: 0.5 * 60 * 1000, // 30 seconds
  max: 100, // limit each IP to 5 requests per windowMs
  keyGenerator: (req, res) => {
    const id = uuidv4();
    req.headers["debug-id"] = id;
    return req.ip.replace(/:\d+[^:]*$/, '') // IP address from requestIp.mw(), as opposed to req.ip
  },
  message: async (req, res) => {
		const ip = req.ip || req.headers['x-forwarded-for'] || null;
    const error = { code: "429", cause: "RATE-LIMIT IP " + ip }
    consoleError(error, req, req.headers["debug-id"]);
    return res.status(429).json({ error: 'Haz superado el número de intentos, por favor intenta en unos minutos.' });
	},
});

const preRegistroLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 10, // limit each IP to 10 requests per windowMs
  keyGenerator: (req, res) => {
    const id = uuidv4();
    req.headers["debug-id"] = id;
    return req.ip.replace(/:\d+[^:]*$/, '') // IP address from requestIp.mw(), as opposed to req.ip
  },
  message: async (req, res) => {
		const ip = req.ip || req.headers['x-forwarded-for'] || null;
    const error = { code: "429", cause: "RATE-LIMIT IP " + ip }
    consoleError(error, req, req.headers["debug-id"]);
    return res.status(429).json({ error: 'Haz superado el número de intentos, por favor intenta en unos minutos.' });
	},
});

const allowedOrigins = ['https://qamiespaciosky.sky.com.mx', 'https://miespaciosky.sky.com.mx', 'https://misky.sky.com.mx'];
if ("development" === env) { // local development purposes
  allowedOrigins.push('https://localhost:3000');
}

// X-Rate-Limiting
app.set('trust proxy', 1)
app.use(limiter);


// CORS
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  preflightContinue: false,
  methods: ['POST', 'GET', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Acceptcrc', 'acceptcrc']
}));

// HSTS
app.use(helmet());
app.use(
  helmet.hsts({
    maxAge: 300,
    includeSubDomains: true,
    preload: true,
  })
);

app.use(express.json())

const {
  REACT_APP_URL_INTERNO,
  REACT_APP_USER_INTERNO,
  REACT_APP_PASSWORD_INTERNO,
  REACT_APP_GOOGLE_API_KEY,
  REACT_APP_RECAPTCHA_KEY
} = process.env;

const CONTENT_ACCEPT_JSON = {
  "Content-type": "application/json",
  Accept: "application/json",
};

const OSB_AUTH = {
  username: REACT_APP_USER_INTERNO ?? "",
  password: REACT_APP_PASSWORD_INTERNO ?? "",
};

const INTERNO_AUTH = {
  username: REACT_APP_USER_INTERNO ?? "",
  password: REACT_APP_PASSWORD_INTERNO ?? "",
};

// listening for port
app.listen(process.env.PORT, '0.0.0.0', () => logger.log("info", `App listening on port ${process.env.PORT}!`));

app.get("/", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  res.json({ message: "Welcome !!!!" });
});

// Handle errors using the logger
app.use((err, req, res, next) => {
  // Log the error message at the error level
  logger.error(err.message);
  res.status(500).send();
});

// API request
app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/generarQueja", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/generarQueja",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: OSB_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      consoleSucess(response, id);
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/crearSugerencia", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url:
      REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/crearSugerencia",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: OSB_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      consoleSucess(response, id);
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post(
  "/EnterpriseServices/Sel/Solicitud/Solicitud/responderEncuesta",
  (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
    const options = {
      method: "POST",
      url:
        REACT_APP_URL_INTERNO +
        "/EnterpriseServices/Sel/Solicitud/responderEncuesta",
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    };

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id);
        res.json(response.data);
      })
      .catch(function (error) {
        consoleError(error, req, id);
        return res.status(500).json({ error: 'ocurrio un error inesperado' });
      });
  }
);

app.post(
  "/EnterpriseServices/Sel/AltaSolicitudDeServicioRest",
  (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
    const options = {
      method: "POST",
      url:
        REACT_APP_URL_INTERNO +
        "/EnterpriseServices/Sel/AltaSolicitudDeServicioRest",
      data: req.body,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    };

    axios
      .request(options)
      .then(function (response) {
        consoleSucess(response, id);
        res.json(response.data);
      })
      .catch(function (error) {
        consoleError(error, req, id);
        return res.status(500).json({ error: 'ocurrio un error inesperado' });
      });
  }
);

app.post("/mi-sky-api/EnterpriseFlows/Sel/AutenticarUsuarioRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/AutenticarUsuarioRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      consoleSucess(response, id);
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaConsumoDatosRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaConsumoDatosRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaDatosGeneralesRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaDatosGeneralesRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaPaqAdicionalDatosRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaPaqAdicionalDatosRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaParrillaGuiaSkyRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaParrillaGuiaSkyRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});



app.post("/mi-sky-api/EnterpriseServices/Sel/GestionarSSComprarServiciosRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/GestionarSSComprarServiciosRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseFlows/Sel/ModificarPasswordRegistroRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/ModificarPasswordRegistroRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ReEnviarEmailPreRegSelEBSRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ReEnviarEmailPreRegSelEBSRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaPagosPorEventoRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaPagosPorEventoRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaPrecioRecargaRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaPrecioRecargaRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarCuentaAsociada", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Cuenta/consultarCuentaAsociada",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarCuentaEspecial", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
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
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/Cuenta/consultarDatosUsuario", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Cuenta/consultarDatosUsuario",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/consultarEstadoCuenta", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/consultarEstadoCuenta",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/consultarFactura", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/consultarFactura",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/consultarFacturaPeriodo", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/consultarFacturaPeriodo",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/Cuenta/consultarLDAP", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Cuenta/consultarLDAP",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/Pago/consultarPago", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Pago/consultarPago",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/PagoEvento/consultarProducto", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/PagoEvento/consultarProducto",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarRegimenFiscalRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarRegimenFiscalRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarServiciosAdicionalesRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarServiciosAdicionalesRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarUsoCFDIRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarUsoCFDIRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaSolicitudDeServicioRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaSolicitudDeServicioRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/crearSolicitud", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/crearSolicitud",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/EjecutarRemoteBookingRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/EjecutarRemoteBookingRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/RegistrarDatosFiscalesRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/RegistrarDatosFiscalesRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/obtenerFactura", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/obtenerFactura",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Okta/Usuario/restablecerContrasena", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Okta/Usuario/restablecerContrasena",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaCuentaRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaCuentaRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/SbConsultaHorariosPagoPorEventoSelEBS/ConsultaHorariosPagoPorEventoRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/SbConsultaHorariosPagoPorEventoSelEBS/ConsultaHorariosPagoPorEventoRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ActivacionBlueToGoRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ActivacionBlueToGoRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ActualizaDatosFiscalesEBFRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ActualizaDatosFiscalesEBFRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaCanalGuiaSkyRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaCanalGuiaSkyRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaControlRemotoRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaControlRemotoRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarDatosFiscalesRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarDatosFiscalesRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarEstadosDeCuentaRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarEstadosDeCuentaRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarFacturaCorporativo", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Cuenta/consultarFacturaCorporativo",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/PagoEvento/consultarPPV", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/PagoEvento/consultarPPV",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarSaldosCorrientesRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarSaldosCorrientesRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarServiciosCuentaRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarServiciosCuentaRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/Equipo/consultarTICorporativo", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Equipo/consultarTICorporativo",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});


app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/enviarEmail", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/enviarEmail",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});


app.post("/mi-sky-api/EnterpriseServices/Sel/GestionarSSComprarDatosRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/GestionarSSComprarDatosRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});


app.post("/mi-sky-api/EnterpriseServices/Okta/Usuario/cambiarContrasena", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Okta/Usuario/cambiarContrasena",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseFlows/Sel/RecuperarPasswordUsrRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/RecuperarPasswordUsrRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseFlows/Sel/PreRegistroRest", preRegistroLimiter, (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  //ip from client
  const ip = req.ip || req.headers['x-forwarded-for'] || null

  // validate token
  const token = req.headers.acceptcrc;

  const validateTokenData = { 
    "event": { 
      "token": token, 
      "expectedAction": "USER_ACTION", 
      "siteKey": REACT_APP_RECAPTCHA_KEY
    } 
  };

  const validateTokenOptions = {
    method: "POST",
    url: "https://recaptchaenterprise.googleapis.com/v1/projects/sel-sky/assessments?key=" + REACT_APP_GOOGLE_API_KEY,
    data: validateTokenData,
    headers:  { 
      "Content-type": "application/json",
      'Accept': "application/json",
    }
  };

  if (!token) {
    const date = new Date(Date.now()).toLocaleString();
    logger.error("NON_TOKEN_FOUND from IP: "+ip, {"id": id});
    return res.status(401).json({ msg: 'Unauthorized user' });
  }

  axios
    .request(validateTokenOptions)
    .then(function (response) {
      const data = response.data
      const reason = data["tokenProperties"].invalidReason;
      if(!data["tokenProperties"].valid && reason !== "DUPE") {
        const date = new Date(Date.now()).toLocaleString();
        logger.error("INVALID_CAPTCHA from IP: " + ip + " | reason: " + reason, {"id": id});
        return res.status(401).json({ msg: 'Unauthorized user' });
      } else { // call OSB
        const options = {
          method: "POST",
          url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/PreRegistroRest",
          data: req.body,
          headers: CONTENT_ACCEPT_JSON,
          auth: INTERNO_AUTH,
        };
      
        axios
          .request(options)
          .then(function (response) {
            res.json(response.data);
          })
          .catch(function (error) {
            consoleError(error, req, id);
            return res.status(500).json({ error: 'ocurrio un error inesperado' });
          });
      }
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(401).json({ msg: 'Unauthorized user' });
    });

});

app.post("/mi-sky-api/EnterpriseFlows/Sel/RegistrarQuejaRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/RegistrarQuejaRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseFlows/Sel/RegistrarSugerenciaRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/RegistrarSugerenciaRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/Equipo/consultarIRD", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Equipo/consultarIRD",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ValidarPreRegistroRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ValidarPreRegistroRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/PagoEvento/consultarPrecio", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/PagoEvento/consultarPrecio",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarInformacionFiscalRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarInformacionFiscalRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarCambioPaquetePrincipalRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarCambioPaquetePrincipalRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaPaqueteRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaPaqueteRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaVeTVPricesRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaVeTVPricesRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarDireccion", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Cuenta/consultarDireccion",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaRevistaSKYRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaRevistaSKYRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/PagoEvento/consultarCanal", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/PagoEvento/consultarCanal",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/Sel/Sesion/consultarMenu", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Sesion/consultarMenu",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseServices/RN/GeneraURLChatRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/RN/GeneraURLChatRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

app.post("/mi-sky-api/EnterpriseFlows/Sel/CrearRegistroRest", (req, res) => {
  const id = uuidv4();
  consoleRequestStart(req, id);
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/CrearRegistroRest",
    data: req.body,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      consoleError(error, req, id);
      return res.status(500).json({ error: 'ocurrio un error inesperado' });
    });
});

function consoleError(error, requestData, id) {
  const errorData   = error.response?.data?.error ?? error.message ?? error;
  const errorCode   = error.code;
  const errorCause  = error.cause;
  const errorUrl    = error.config?.url;
  const errorMethod    = error.config?.method;
  const body = requestData.body;
  if(body && body.AutenticarUsuarioInputMessage?.Password) {
    body.AutenticarUsuarioInputMessage.Password = "ENCRYPTED_AND_OMMITED";
  }

  logger.error(
    'code: ' + errorCode + " | " + 
    'error: ' + JSON.stringify(errorData) + " | " + 
    'cause: ' + JSON.stringify(errorCause) + " | " + 
    "url: " + errorUrl + " | " + 
    'method: ' + errorMethod + " | " + 
    'requestData: '+JSON.stringify(body, null, 2),
    {"_id": id, "_timestamp":  getCurrentDate()}
  );
  
}

function consoleRequestStart(req, id) {
  logger.info(" | url: " + req.path + " | method: " + req.method + " | Request received: " + JSON.stringify(req.body), {"_id": id, "_timestamp":  getCurrentDate()});
}

function consoleSucess(response, id) {
  logger.info('status: ' + response.statusCode + " | " +  'url: ' + response.request?.uri?.href + " | " +  'response: ' + JSON.stringify(response.body), {"_id": id, "_timestamp":  getCurrentDate()})
}

function getCurrentDate() {
  return new Date(Date.now()).toLocaleString();
}