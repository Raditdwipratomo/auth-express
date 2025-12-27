import mongoose from "mongoose";

export async function connectToDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI!);
    console.log("mongo connection is successfully established");
  } catch (error) {
    console.error("Mongo db connection Error!");
    process.exit(1);
  }
}
