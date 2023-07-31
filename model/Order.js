const mongoose = require('mongoose');
const { Schema } = mongoose;

const orderSchema = new Schema({
    items: { type: [Schema.Types.Mixed], required: true },
    selectAddress: { type: Schema.Types.Mixed, required: true },
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    totalAmount: { type: Number },
    totalItems: { type: Number },
    paymentMethod: { type: String, required: true },
    status: { type: String, default: 'pending' },

});

const virtual = orderSchema.virtual('id');
virtual.get(function () {
    return this._id;
});
orderSchema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    transform: function (doc, ret) {
        delete ret._id;
    },
});

exports.Order = mongoose.model('Order', orderSchema);