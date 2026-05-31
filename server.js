require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();
app.options('*', cors());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS','PATCH'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json());
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date() }));

const { createClient } = require('@supabase/supabase-js');
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const auth = require('./middleware/auth');

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from('expense_tracker_users').insert([{ email, password: hashedPassword, name }]);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        const token = jwt.sign({ id: data[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const { data, error } = await supabase.from('expense_tracker_users').select('*').eq('email', email);
        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        const isValidPassword = await bcrypt.compare(password, data[0].password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }
        const token = jwt.sign({ id: data[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/auth/me', auth.verifyToken, async (req, res) => {
    try {
        const { id } = req.user;
        const { data, error } = await supabase.from('expense_tracker_users').select('*').eq('id', id);
        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(data[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/expenses', auth.verifyToken, async (req, res) => {
    try {
        const { title, amount, category } = req.body;
        const { id } = req.user;
        const { data, error } = await supabase.from('expense_tracker_expenses').insert([{ title, amount, category, user_id: id }]);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        res.json(data[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/expenses', auth.verifyToken, async (req, res) => {
    try {
        const { id } = req.user;
        const { data, error } = await supabase.from('expense_tracker_expenses').select('*').eq('user_id', id);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/expenses/:id', auth.verifyToken, async (req, res) => {
    try {
        const { id: expenseId } = req.params;
        const { id: userId } = req.user;
        const { data, error } = await supabase.from('expense_tracker_expenses').select('*').eq('id', expenseId).eq('user_id', userId);
        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: 'Expense not found' });
        }
        await supabase.from('expense_tracker_expenses').delete().eq('id', expenseId);
        res.json({ message: 'Expense deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/expenses/summary', auth.verifyToken, async (req, res) => {
    try {
        const { id } = req.user;
        const { data, error } = await supabase.from('expense_tracker_expenses').select('category, sum(amount) as total_amount').eq('user_id', id).group('category');
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server started on port ${port}`));