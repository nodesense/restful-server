// susbcribe from same  topic

queue_name = "rating_reviews_update"

// not for your project
function bail(err) {
    console.error(err);
    process.exit(1);
  }

// Consumer
function consumer(conn) {
    var ok = conn.createChannel(on_open);
    function on_open(err, ch) {
      if (err != null) bail(err);
      ch.assertQueue(queue_name);
      ch.consume(queue_name, function(msg) {
        if (msg !== null) {
            const content = msg.content.toString()
          console.log(content);
          const raview_rating = JSON.parse(content)
          console.log("received ", raview_rating)
          ch.ack(msg);
        }
      });
    }
  }

require('amqplib/callback_api')
  .connect('amqps://yourid:yourpass@beaver.rmq.cloudamqp.com/yourid', function(err, conn) {
    if (err != null) bail(err);
    consumer(conn);
    
  });
