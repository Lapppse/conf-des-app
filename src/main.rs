#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use bitvec::prelude::*;
use des_ndtp::{Block, Error, FromHexStr, MainKey, ToHexString};
use iced::widget::{button, column, container, horizontal_space, row, text, text_input};
use iced::{
    executor, window, Alignment, Application, Command, Element, Length, Settings, Size, Theme,
};

fn main() -> iced::Result {
    let settings = Settings {
        window: window::Settings {
            min_size: Some(Size {
                height: 600.0,
                width: 800.0,
            }),
            resizable: true,
            decorations: true,
            ..Default::default()
        },
        ..Default::default()
    };
    DesApp::run(settings)
}

#[derive(Debug, Clone)]
pub enum InputType {
    Text,
    Key,
    IV,
}

#[derive(Debug, Clone)]
pub enum Message {
    Input {
        input: String,
        input_type: InputType,
    },
    EncodedTextComputed(BitVec),
    ChangeTheme,
    Ignore(String),
}

#[derive(Debug, Default, Clone)]
pub struct DesApp {
    cipher: Option<BitVec>,
    key: Option<MainKey>,
    iv: Option<Block>,
    encoded: Option<BitVec>,
    cipher_input: String,
    key_input: String,
    iv_input: String,
    theme: Theme,
    error: (Option<Error>, Option<Error>, Option<Error>),
}

async fn encode(input: BitVec, key: MainKey, iv: Block) -> BitVec {
    let iv = iv.encode(&key).unwrap().into_bitvec();
    let mut output: BitVec<usize, bitvec::order::LocalBits> = BitVec::with_capacity(input.len());
    let input = input.chunks(64);
    for chunk in input {
        let mut new_chunk = chunk.to_bitvec();
        new_chunk ^= iv.clone();
        output.extend(new_chunk);
    }
    output
}

impl Application for DesApp {
    type Message = Message;
    type Theme = Theme;
    type Executor = executor::Default;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
        (
            Self {
                cipher: None,
                key: None,
                iv: None,
                encoded: None,
                cipher_input: String::default(),
                key_input: String::default(),
                iv_input: String::default(),
                theme: Theme::Dark,
                error: (None, None, None),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        "Anonymization example".to_string()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        let mut changed = false;
        match message {
            Message::Input { input, input_type } => match input_type {
                InputType::Text => {
                    self.cipher_input = input.to_uppercase();
                    if input.is_empty() {
                        self.cipher = None;
                    }
                    match BitVec::from_hex_str(&self.cipher_input) {
                        Ok(cipher) => {
                            self.cipher = Some(cipher);
                            self.error.0 = None;
                        }
                        Err(e) => {
                            self.cipher = None;
                            self.error.0 = Some(e);
                        }
                    }
                    changed = true;
                }
                InputType::Key => {
                    if input.len() <= 16 {
                        self.key_input = input.to_uppercase();
                    }
                    if self.key_input.len() == 16 {
                        match MainKey::from_hex_str(&self.key_input) {
                            Ok(key) => {
                                self.key = Some(key);
                                self.error.1 = None
                            }
                            Err(e) => {
                                self.key = None;
                                self.error.1 = Some(e);
                            }
                        }
                        changed = true;
                    }
                }
                InputType::IV => {
                    if input.len() <= 16 {
                        self.iv_input = input.to_uppercase();
                    }
                    if self.iv_input.len() == 16 {
                        match Block::from_hex_str(&self.iv_input) {
                            Ok(iv) => {
                                self.iv = Some(iv);
                                self.error.2 = None
                            }
                            Err(e) => {
                                self.iv = None;
                                self.error.2 = Some(e);
                            }
                        }
                        changed = true;
                    }
                }
            },
            Message::EncodedTextComputed(cipher) => self.encoded = Some(cipher),
            Message::ChangeTheme => {
                if self.theme == Theme::Dark {
                    self.theme = Theme::Light;
                } else {
                    self.theme = Theme::Dark;
                }
            }
            Message::Ignore(_) => {}
        }

        if self.cipher.is_some() && self.key.is_some() && self.iv.is_some() {
            if !changed {
                return Command::none();
            }
            let input = BitVec::from_hex_str(&self.cipher_input).unwrap();
            return Command::perform(
                encode(input, self.key.clone().unwrap(), self.iv.clone().unwrap()),
                Message::EncodedTextComputed,
            );
        } else {
            self.encoded = None;
        }

        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let inputs = row![
            horizontal_space(Length::FillPortion(1)),
            column![
                text_input("Input text", &self.cipher_input)
                    .on_input(|input| {
                        Message::Input {
                            input,
                            input_type: InputType::Text,
                        }
                    })
                    .size(24),
                text_input("Input Main Key", &self.key_input)
                    .on_input(|input| {
                        Message::Input {
                            input,
                            input_type: InputType::Key,
                        }
                    })
                    .size(24),
                text_input("Input IV", &self.iv_input)
                    .on_input(|input| {
                        Message::Input {
                            input,
                            input_type: InputType::IV,
                        }
                    })
                    .size(24),
            ]
            .width(Length::FillPortion(6)),
            horizontal_space(Length::FillPortion(1))
        ]
        .align_items(Alignment::Center)
        .spacing(10);

        let mut outputs = column![].spacing(10).align_items(Alignment::Center);
        if let Some(error) = &self.error.0 {
            outputs = outputs.push(text(format!("Error: {}", error)))
        }
        if let Some(error) = &self.error.1 {
            outputs = outputs.push(text(format!("Error: {}", error)))
        }
        if let Some(error) = &self.error.2 {
            outputs = outputs.push(text(format!("Error: {}", error)))
        }

        if !self.cipher_input.is_empty() {
            outputs = outputs.push(text(format!("Input: {}", &self.cipher_input)))
        }
        if let Some(key) = &self.key {
            outputs = outputs.push(text(format!("Main Key: {}", key.to_upper_hex())))
        }
        if let Some(iv) = &self.iv {
            outputs = outputs.push(text(format!("IV: {}", iv.to_upper_hex())))
        }
        let mut encoded_button_value = String::new();
        if let Some(encoded) = &self.encoded {
            encoded_button_value = encoded.to_upper_hex();
        }
        outputs = outputs.push(
            text_input(
                "Encoded value will appear here",
                encoded_button_value.as_str(),
            )
            .on_input(Message::Ignore),
        );
        let outputs = row![
            horizontal_space(Length::FillPortion(1)),
            container(outputs).width(Length::FillPortion(6)),
            horizontal_space(Length::FillPortion(1))
        ];

        let content = column![
            button("Change appearance").on_press(Message::ChangeTheme),
            inputs,
            outputs
        ]
        .padding(20)
        .spacing(40)
        .align_items(Alignment::Center);

        container(content).center_y().into()
    }

    fn theme(&self) -> Theme {
        self.theme.clone()
    }
}
