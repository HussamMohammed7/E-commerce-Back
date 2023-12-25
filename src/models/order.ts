import mongoose from 'mongoose'
import {OrderStatus} from "../types/orders";

export type OrderDocument = Document & {
    userId:string,
    products:{product: string, quantity: number}[],
    date: Date,
    status:OrderStatus
}

const orderSchema = new mongoose.Schema({
  userId:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Client'
  } ,
  products:[
    {
      product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
      },
      quantity:{
        type: Number,
        required: true,
      },
      price:{
        type: Number,
        required: true,
      },
  }
  ],
  status:{
    type:String,
    enum: ["under process", "shopped", "finished", "canceled"],
    required: true,
    default:"under process"
  },
  purchasedAt:{
    type:Date,
    required:true,
    default:Date.now()
  },
  total:{
    type: Number,
    required: false,
  },
})

export default mongoose.model<OrderDocument>('Order', orderSchema)
