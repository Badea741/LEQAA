const mongoose = require("mongoose");
const { v1: uuidv4 } = require("uuid");
var uuid = require("node-uuid");

const chatModel = mongoose.Schema(
  {
    chatName: { type: String, trim: true },
    isGroupChat: { type: Boolean, default: false },
    users: [{ type: String, default: uuid.v1, ref: "User" }],
    latestMessage: {
      type: String,
      ref: "Message",
    },
    groupAdmin: { type: String, default: uuid.v1, ref: "User" },
  },
  { timestamps: true }
);

const Chat = mongoose.model("Chat", chatModel);

module.exports = Chat;
