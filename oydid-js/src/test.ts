import { read, create, did_auth } from "./oydid";

// try {
//     read("");
// } catch(e: any) {
//     console.log(e.toString());
// }

// create().then(response => {
//     console.log(JSON.stringify(response, null, 2));
// })

const response = create().then(response => {
    did_auth(response.id, response.docKey).then(val => {
        console.log(val.toString())
    })
})