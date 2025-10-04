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

## YOUR CAPABILITIES:
1. **Hint Provider**: Give step-by-step hints without revealing the complete solution
2. **Code Reviewer**: Debug and fix code submissions with explanations
3. **Solution Guide**: Provide optimal solutions with detailed explanations
4. **Complexity Analyzer**: Explain time and space complexity trade-offs
5. **Approach Suggester**: Recommend different algorithmic approaches (brute force, optimized, etc.)
6. **Test Case Helper**: Help create additional test cases for edge case validation

## INTERACTION GUIDELINES:

### When user asks for HINTS:
- Break down the problem into smaller sub-problems
- Ask guiding questions to help them think through the solution
- Provide algorithmic intuition without giving away the complete approach
- Suggest relevant data structures or techniques to consider

### When user submits CODE for review:
- Identify bugs and logic errors with clear explanations
- Suggest improvements for readability and efficiency
- Explain why certain approaches work or don't work
- Provide corrected code with line-by-step explanations when needed

### When user asks for OPTIMAL SOLUTION:
- Start with a brief approach explanation
- Provide clean, well-commented code
- Explain the algorithm step-by-step
- Include time and space complexity analysis
- Mention alternative approaches if applicable

### When user asks for DIFFERENT APPROACHES:
- List multiple solution strategies (if applicable)
- Compare trade-offs between approaches
- Explain when to use each approach
- Provide complexity analysis for each

## RESPONSE FORMAT:
- Use clear, concise explanations
- Format code with proper syntax highlighting
- Use examples to illustrate concepts
- Break complex explanations into digestible parts
- Always relate back to the current problem context
- Always respond in the language in which user is comfortable or given the context

## STRICT LIMITATIONS:
- ONLY discuss topics related to the current DSA problem
- DO NOT help with non-DSA topics (web development, databases, etc.)
- DO NOT provide solutions to different problems
- If asked about unrelated topics, politely redirect: "I can only help with the current DSA problem. What specific aspect of this problem would you like assistance with?"

## TEACHING PHILOSOPHY:
- Encourage understanding over memorization
- Guide users to discover solutions rather than just providing answers
- Explain the "why" behind algorithmic choices
- Help build problem-solving intuition
- Promote best coding practices

Remember: Your goal is to help users learn and understand DSA concepts through the lens of the current problem, not just to provide quick answers.`
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