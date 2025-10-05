const { GoogleGenerativeAI } = require("@google/generative-ai");

const solveDoubt = async (req, res) => {
  try {
    const { messages, title, description, testCases, startCode } = req.body;

    // Verify API key
    if (!process.env.GOOGLE_API_KEY) {
      return res.status(500).json({
        message: "API key not configured"
      });
    }

    // Initialize the Google Generative AI client
    const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

    // Get the generative model with system instruction
    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash", 
      systemInstruction: `You are an expert Data Structures and Algorithms (DSA) tutor specializing in helping users solve coding problems. Your role is strictly limited to DSA-related assistance only.

## CURRENT PROBLEM CONTEXT:
[PROBLEM_TITLE]: ${title || 'Not provided'}
[PROBLEM_DESCRIPTION]: ${description || 'Not provided'}
[EXAMPLES]: ${testCases || 'Not provided'}
[START_CODE]: ${startCode || 'Not provided'}


`
    });

    let result;
    let userPrompt;

    // Handle different message formats
    if (typeof messages === 'string') {
      // Simple string message
      userPrompt = messages;
      result = await model.generateContent(userPrompt);
    } 
    else if (Array.isArray(messages) && messages.length > 0) {
      // Array of messages - use chat mode
      
      // Map messages and ensure proper role names
      const formattedMessages = messages.map(msg => ({
        role: msg.role === 'assistant' || msg.role === 'model' ? 'model' : 'user',
        parts: [{ text: msg.content || msg.text || msg.message || '' }]
      }));

      // Ensure the first message is from 'user'
      if (formattedMessages[0].role !== 'user') {
        return res.status(400).json({
          message: "Chat history must start with a user message"
        });
      }

      // Get history (all except last message) and current message
      const history = formattedMessages.slice(0, -1);
      const lastMsg = formattedMessages[formattedMessages.length - 1];
      userPrompt = lastMsg.parts[0].text;

      if (history.length > 0) {
        const chat = model.startChat({ history });
        result = await chat.sendMessage(userPrompt);
      } else {
        result = await model.generateContent(userPrompt);
      }
    } 
    else if (typeof messages === 'object' && messages !== null) {
      // Single message object
      userPrompt = messages.content || messages.text || messages.message || '';
      result = await model.generateContent(userPrompt);
    } 
    else {
      return res.status(400).json({
        message: "Invalid messages format"
      });
    }

    const responseText = result.response.text();

    res.status(200).json({
      message: responseText
    });

    console.log("AI Response generated successfully");

  } catch (err) {
    console.error("Error generating AI response:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  }
};

module.exports = solveDoubt;