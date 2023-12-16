import mongoose from 'mongoose'


const userSchema = new mongoose.Schema({
 
  first_name: {
    type: String,
    required: true,
  },
  last_name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  phone: {
    type: String,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['visitor', 'admin'],
    required: true,
    
    default:"visitor"
  },
  avatar: {
    type: String,
  },
  isActive: {
    type: Boolean,
    default: false,
  },
  address: {
    type: [String],
  },
  
  activationToken: {
    type: String,
  },
  // relation between order and user should be many orders to one user
  // here's 1to1 just for the demo
  order: {
    type:[mongoose.Schema.Types.ObjectId] ,

    ref: 'Order',
  },

})

export default mongoose.model('Client', userSchema)
