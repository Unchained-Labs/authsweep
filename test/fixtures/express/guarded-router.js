const express = require('express')
const router = express.Router()
const { requireAuth } = require('./auth')

// a router-level guard covers everything below it
router.use(requireAuth)

router.get('/orders', (req, res) => res.json(orders(req.user)))
router.post('/orders', (req, res) => createOrder(req.user, req.body))
router.delete('/orders/:id', (req, res) => cancel(req.params.id))

module.exports = router
