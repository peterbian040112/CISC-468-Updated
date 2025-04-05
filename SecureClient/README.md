

## Folder Structure

The workspace contains two folders by default, where:

- `src`: the folder to maintain sources
- `lib`: the folder to maintain dependencies

Meanwhile, the compiled output files will be generated in the `bin` folder by default.


## Usage

Since the project is managed by vscode, we'll use vscode help us compile. Click the run and in the command line, type the following:

> java -cp "bin;lib/jmdns-3.6.0.jar;lib/slf4j-api-1.7.36.jar;lib/slf4j-simple-1.7.36.jar;lib/bcprov-jdk18on-1.80.jar" SecureShareClient JavaClient --port 8080

> help 

will list all the command 
