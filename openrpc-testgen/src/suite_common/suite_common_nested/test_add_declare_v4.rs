use crate::RunnableTrait;

pub struct TestCase {
    pub tmp: String,
}

impl RunnableTrait for TestCase {
    fn run(&self) {
        println!("COMMON NESTED V3");
    }
}
