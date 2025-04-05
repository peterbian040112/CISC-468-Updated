## Getting Started

Welcome to the VS Code Java world. Here is a guideline to help you get started to write Java code in Visual Studio Code.

## Folder Structure

The workspace contains two folders by default, where:

- `src`: the folder to maintain sources
- `lib`: the folder to maintain dependencies

Meanwhile, the compiled output files will be generated in the `bin` folder by default.

> If you want to customize the folder structure, open `.vscode/settings.json` and update the related settings there.

## Usage

Since the project is managed by vscode, we'll use vscode help us compile. Click the run and in the command line, type the following:

> java -cp "bin;lib/jmdns-3.6.0.jar;lib/slf4j-api-1.7.36.jar;lib/slf4j-simple-1.7.36.jar;lib/bcprov-jdk18on-1.80.jar" SecureShareClient JavaClient --port 8080

and in line 122

`this.jmdns = JmDNS.create("172.20.10.3");`

we set the start server ip address manually for easy testing

it should be `this.jmdns = JmDNS.create(localAddress.getHostAddress());` in the final version.
