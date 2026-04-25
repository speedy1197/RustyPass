use anyhow::Result;
use crossterm::event::{self, Event};

use russty_pass::{App, setup_terminal, restore_terminal, ui};

fn main() -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = App::new();

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if app.handle_key_event(key)? {
                break;
            }
        }
    }

    restore_terminal()?;
    Ok(())
}