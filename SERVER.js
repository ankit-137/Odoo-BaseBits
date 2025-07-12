require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const { check, validationResult } = require('express-validator');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bodyParser = require('body-parser');

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(helmet());
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/stackit', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB Connection Error:', err));

// Models
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  avatar: { type: String, default: function() { return this.username.charAt(0).toUpperCase(); } },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  reputation: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);

const QuestionSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  body: { type: String, required: true },
  tags: [{ type: String, trim: true, lowercase: true }],
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  votes: { type: Number, default: 0 },
  voters: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    vote: { type: Number, enum: [1, -1] }
  }],
  answers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Answer' }],
  views: { type: Number, default: 0 },
  acceptedAnswer: { type: mongoose.Schema.Types.ObjectId, ref: 'Answer' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

QuestionSchema.index({ title: 'text', body: 'text', tags: 'text' });
const Question = mongoose.model('Question', QuestionSchema);

const AnswerSchema = new mongoose.Schema({
  body: { type: String, required: true },
  question: { type: mongoose.Schema.Types.ObjectId, ref: 'Question', required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  votes: { type: Number, default: 0 },
  voters: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    vote: { type: Number, enum: [1, -1] }
  }],
  isAccepted: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Answer = mongoose.model('Answer', AnswerSchema);

const NotificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['answer', 'mention', 'vote', 'accept'], required: true },
  question: { type: mongoose.Schema.Types.ObjectId, ref: 'Question' },
  answer: { type: mongoose.Schema.Types.ObjectId, ref: 'Answer' },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', NotificationSchema);

// Passport JWT Strategy
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET || 'your_jwt_secret'
};

passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
  try {
    const user = await User.findById(jwt_payload.user.id);
    if (user) return done(null, user);
    return done(null, false);
  } catch (err) {
    return done(err, false);
  }
}));

app.use(passport.initialize());

// Middleware Functions
const protect = passport.authenticate('jwt', { session: false });

const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ msg: 'Not authorized as admin' });
  }
};

const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: 'Server error' });
};

// Routes
// Auth Routes
app.post('/api/auth/register', [
  check('username', 'Username is required').not().isEmpty(),
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    user = new User({ username, email, password });
    await user.save();

    const payload = { user: { id: user.id } };
    jwt.sign(payload, opts.secretOrKey, { expiresIn: '7d' }, (err, token) => {
      if (err) throw err;
      res.json({ token });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.post('/api/auth/login', [
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const payload = { user: { id: user.id } };
    jwt.sign(payload, opts.secretOrKey, { expiresIn: '7d' }, (err, token) => {
      if (err) throw err;
      res.json({ 
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          avatar: user.avatar,
          role: user.role
        }
      });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/auth/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Question Routes
app.get('/api/questions', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    let query = {};
    if (req.query.search) query = { $text: { $search: req.query.search } };
    if (req.query.tag) query.tags = req.query.tag;

    const questions = await Question.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('author', 'username avatar')
      .populate('answers');

    const total = await Question.countDocuments(query);
    res.json({ questions, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/questions/:id', async (req, res) => {
  try {
    const question = await Question.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true }
    )
      .populate('author', 'username avatar reputation')
      .populate({
        path: 'answers',
        populate: { path: 'author', select: 'username avatar reputation' }
      });

    if (!question) return res.status(404).json({ msg: 'Question not found' });
    res.json(question);
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'Question not found' });
    res.status(500).send('Server error');
  }
});

app.post('/api/questions', [
  protect,
  [
    check('title', 'Title is required').not().isEmpty(),
    check('body', 'Body is required').not().isEmpty(),
    check('tags', 'Tags are required').not().isEmpty()
  ]
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { title, body, tags } = req.body;

  try {
    const question = new Question({
      title,
      body,
      tags: tags.split(',').map(tag => tag.trim().toLowerCase()),
      author: req.user.id
    });

    await question.save();
    res.status(201).json(question);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.put('/api/questions/:id/vote', [
  protect,
  [check('vote', 'Vote is required and must be 1 or -1').isIn([1, -1])]
], async (req, res) => {
  try {
    const question = await Question.findById(req.params.id);
    if (!question) return res.status(404).json({ msg: 'Question not found' });

    const { vote } = req.body;
    const existingVote = question.voters.find(v => v.user.toString() === req.user.id);

    if (existingVote) {
      if (existingVote.vote === vote) {
        question.votes -= vote;
        question.voters = question.voters.filter(v => v.user.toString() !== req.user.id);
      } else {
        question.votes += 2 * vote;
        existingVote.vote = vote;
      }
    } else {
      question.votes += vote;
      question.voters.push({ user: req.user.id, vote });
    }

    await question.save();

    if (question.author.toString() !== req.user.id) {
      const author = await User.findById(question.author);
      if (author) {
        author.reputation += vote * (vote === 1 ? 10 : -2);
        await author.save();
      }
    }

    res.json(question);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/questions/tag/:tag', async (req, res) => {
  try {
    const questions = await Question.find({ tags: req.params.tag })
      .sort({ createdAt: -1 })
      .populate('author', 'username avatar');
    res.json(questions);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/questions/tags/popular', async (req, res) => {
  try {
    const tags = await Question.aggregate([
      { $unwind: '$tags' },
      { $group: { _id: '$tags', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    res.json(tags);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Answer Routes
app.post('/api/questions/:id/answers', [
  protect,
  [check('body', 'Body is required').not().isEmpty()]
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const question = await Question.findById(req.params.id);
    if (!question) return res.status(404).json({ msg: 'Question not found' });

    const answer = new Answer({
      body: req.body.body,
      question: req.params.id,
      author: req.user.id
    });

    await answer.save();
    question.answers.push(answer._id);
    await question.save();

    if (question.author.toString() !== req.user.id) {
      await Notification.create({
        recipient: question.author,
        sender: req.user.id,
        type: 'answer',
        question: question._id,
        answer: answer._id
      });
    }

    res.status(201).json(answer);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.put('/api/answers/:id/vote', [
  protect,
  [check('vote', 'Vote is required and must be 1 or -1').isIn([1, -1])]
], async (req, res) => {
  try {
    const answer = await Answer.findById(req.params.id);
    if (!answer) return res.status(404).json({ msg: 'Answer not found' });

    const { vote } = req.body;
    const existingVote = answer.voters.find(v => v.user.toString() === req.user.id);

    if (existingVote) {
      if (existingVote.vote === vote) {
        answer.votes -= vote;
        answer.voters = answer.voters.filter(v => v.user.toString() !== req.user.id);
      } else {
        answer.votes += 2 * vote;
        existingVote.vote = vote;
      }
    } else {
      answer.votes += vote;
      answer.voters.push({ user: req.user.id, vote });
    }

    await answer.save();

    if (answer.author.toString() !== req.user.id) {
      const author = await User.findById(answer.author);
      if (author) {
        author.reputation += vote * (vote === 1 ? 10 : -2);
        await author.save();
      }
    }

    res.json(answer);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.put('/api/answers/:id/accept', protect, async (req, res) => {
  try {
    const answer = await Answer.findById(req.params.id).populate('question', 'author acceptedAnswer');
    if (!answer) return res.status(404).json({ msg: 'Answer not found' });

    if (answer.question.author.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'Not authorized' });
    }

    if (answer.question.acceptedAnswer && answer.question.acceptedAnswer.toString() !== req.params.id) {
      const prevAnswer = await Answer.findById(answer.question.acceptedAnswer);
      if (prevAnswer) {
        prevAnswer.isAccepted = false;
        await prevAnswer.save();
      }
    }

    answer.isAccepted = !answer.isAccepted;
    await answer.save();

    answer.question.acceptedAnswer = answer.isAccepted ? answer._id : null;
    await answer.question.save();

    if (answer.isAccepted && answer.author.toString() !== req.user.id) {
      await Notification.create({
        recipient: answer.author,
        sender: req.user.id,
        type: 'accept',
        question: answer.question._id,
        answer: answer._id
      });

      const author = await User.findById(answer.author);
      if (author) {
        author.reputation += 15;
        await author.save();
      }
    }

    res.json(answer);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// User Routes
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password').lean();
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const [questions, answers] = await Promise.all([
      Question.find({ author: req.params.id }).sort({ createdAt: -1 }).lean(),
      Answer.find({ author: req.params.id }).populate('question', 'title').sort({ createdAt: -1 }).lean()
    ]);

    res.json({ ...user, questions, answers });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'User not found' });
    res.status(500).send('Server error');
  }
});

app.get('/api/users/notifications', protect, async (req, res) => {
  try {
    const notifications = await Notification.find({ recipient: req.user.id })
      .sort({ createdAt: -1 })
      .limit(20)
      .populate('sender', 'username avatar')
      .populate('question', 'title')
      .populate('answer');

    await Notification.updateMany(
      { recipient: req.user.id, read: false },
      { $set: { read: true } }
    );

    res.json(notifications);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/users/notifications/count', protect, async (req, res) => {
  try {
    const count = await Notification.countDocuments({
      recipient: req.user.id,
      read: false
    });
    res.json({ count });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Error Handling Middleware
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));