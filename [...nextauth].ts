import NextAuth from "next-auth";
import bcrypt from "bcryptjs"
import CredentialProvider from "next-auth/providers/credentials";
import dbConnect from "../../../config/dbConnect";
import User from "../../../models/User"
import { NEXTAUTH_SECRECT } from "../../../config";
import { UserInterface, UserSession } from "../../types/interface";



export default NextAuth({
    providers: [
        CredentialProvider({
            name: "Credentials",
            id: 'username-login',
            credentials: {
                username: {
                    label: "Email",
                    type: "text",
                    placeholder: "johndoe@test.com",
                },
                password: { label: "Password", type: "password" },
            },
            authorize: async (credentials) => {
                // database look up
                await dbConnect();

                const user: UserInterface = await User.findOne({ email: credentials?.username }).populate("company");


                if (!user) { throw new Error("No User Found With Email") }
                if (!user.company) { throw new Error("You are not a member of any company, contact us support to get help") }

                const isMatch = await bcrypt.compare(credentials?.password, user.password);

                if (!isMatch) { throw new Error("Invalid Password") }

                const session: UserSession = {
                    id: user._id,
                    companyId: user.company._id,
                    email: user.email,
                    fname: user.firstName,
                    lname: user.lastName,
                    role: user.role,
                    telephone: user.telephone,
                    createdAt: user.createdAt,
                    company: user.company,
                }


                return session;

            },
        }),
    ],

    callbacks: {

        jwt: ({ token, user }) => {
            // first time jwt callback is run, user object is available
            if (user) {

                // console.log("THE USER OBJECT", user)

                token.id = user.id;
                token.companyId = user.companyId;
                token.fname = user.fname;
                token.lname = user.lname;
                token.role = user.role;
                token.telephone = user.telephone;
                token.createdAt = user.createdAt;


                // console.log("FROM NEXT JWT AUTH===>",token, user)
            }
            return token;
        },

        session: ({ session, token, user }) => {

            if (token) {

                session.id = token.id;
                session.companyId = token.companyId;
                session.fname = token.fname;
                session.lname = token.lname;
                session.role = token.role;
                session.telephone = token.telephone;
                session.createdAt = token.createdAt;



                // console.log("FROM NEXT Session AUTH===>",
                //  session, token,
                //   user)
            }

            return session;
        },


    },


    secret: NEXTAUTH_SECRECT,

    session: {
        maxAge: 10 * 60, // 10 Minutes (Sign out user after 10 minutes of inactivity)
        strategy: 'jwt'
    },

    // jwt: {
    //     secret: NEXTAUTH_SECRECT,
    //     encryption: true,
    //     maxAge: 10 * 60,  // 10 Minutes (Sign out user after 10 minutes of inactivity)
    // },

    pages: {
        signIn: "/auth/signin",
        signOut: "/auth/signout",
        error: "/auth/signin",
        // verifyRequest: "http://localhost:3000/auth/signin",
    },

});
