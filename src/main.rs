#[macro_use]
extern crate rocket;
extern crate chrono;
extern crate sha256;

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use rocket::{
    response::{content::RawHtml, Redirect},
    State,
};

const PASSWORD: &str = "c0b64d1606154e4b00c76657a5d83a16a9a9cfe0143831bb2b0aa87c2d2ca83f";
const HTML_BEGIN: &str = r#"
<html>
	<style>
		table, th, td {
			border: 2px solid black;
		}

		table {
			width: 100%;
		}

		td {
			padding: 1rem 0rem;
			text-align: center;
		}

		html {
			background-color: #333;
			color: white;
		}
	</style>
	<body>
		<table><tr><th>IP Address</th><th>Timestamp</th></tr>
"#;

pub struct IpAddrLog {
    pub addr: IpAddr,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

// get "/" with url query called "url", redirect to that url after logging
#[get("/?<url>")]
fn index(url: String, req: IpAddr, logs: &State<Arc<Mutex<Vec<IpAddrLog>>>>) -> Redirect {
    logs.lock().unwrap().push(IpAddrLog {
        addr: req,
        timestamp: chrono::Local::now(),
    });
    Redirect::to(url)
}

#[get("/admin?<password>")]
fn admin(password: String, logs: &State<Arc<Mutex<Vec<IpAddrLog>>>>) -> RawHtml<String> {
    if sha256::digest(password) == PASSWORD {
        let logs = logs.lock().unwrap();
        let mut html = String::from(HTML_BEGIN);
        for log in logs.iter() {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                log.addr, log.timestamp
            ));
        }
        html.push_str("</table></body></html>");
        RawHtml(html)
    } else {
        RawHtml("Unauthorized".to_string())
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .configure(rocket::Config::figment().merge(("port", 9897)))
        .manage(Arc::new(Mutex::new(Vec::<IpAddrLog>::new())))
        .mount("/", routes![index])
        .mount("/", routes![admin])
}
