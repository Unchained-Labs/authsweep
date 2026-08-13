const express = require('express')
const app = express()
const { requireAuth, requireAdmin } = require('./auth')

// conventionally public — must be prefiltered
app.get('/health', (req, res) => res.send('ok'))
app.get('/metrics', (req, res) => res.send(''))
app.post('/auth/login', (req, res) => login(req, res))

// guarded — must be prefiltered
app.get('/me', requireAuth, (req, res) => res.json(req.user))
app.delete('/admin/users/:id', requireAdmin, (req, res) => removeUser(req.params.id))

// explicitly public — must be prefiltered
app.get('/pricing', (req, res) => res.json(PRICES)) // public marketing page

// REAL GAPS
app.delete('/admin/users/:id/roles', (req, res) => dropRoles(req.params.id))
app.post('/billing/charge', (req, res) => charge(req.body))
app.get('/users/:id/export', (req, res) => dumpUser(req.params.id))
app.get('/search', (req, res) => res.json(search(req.query.q)))

// a stub — must be prefiltered
app.put('/todo', (req, res) => res.sendStatus(501))

module.exports = app
