const db = require('../pgConnect');

exports.post = async (user) => {
    console.log(user);
    console.log('SignUp Model');
    try {
        const result = await db.sql`INSERT INTO users (username, email, password) VALUES (${user.username}, ${user.email}, ${user.password}) RETURNING *`;
        //sql`INSERT INTO users (username, password, email) VALUES (${user.username}, ${user.password}, ${user.email}) returning *`;
        return result;
    } catch(error) {
        console.log(error);
        // return message, example: if user creates account with existing email
    }  

    /* const [results, metadata] = await sequelize.query(`SELECT * FROM users`);
    console.log('Here are the results', results);
    console.log('Here is the metadata', metadata);
    return results; */
};