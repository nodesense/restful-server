// publish and susbcribe happens over a channel/queue
//  queue: rating_reviews_update

queue_name = "rating_reviews_update"

function bail(err) {
    console.error(err);
    process.exit(1);
  }
// example code to publish using  a timer
// in your project, whenever new rating/update posted, you need to publish
    // do avg rating/aggergated calculation and publish avg rating

function publisher(conn) {
    setInterval ( () =>  {
        const rating_update = {
            restId: Math.ceil(Math.random() * 1000000),
            rating:   Math.ceil(Math.random() * 5), // average rating
            rating_count:   Math.ceil(Math.random() * 10000), // total ratings
        }
        // TODO: Publish to queue
        console.log("publishing", rating_update)

        conn.createChannel(on_open);
            function on_open(err, ch) {
                if (err != null) bail(err);
                ch.assertQueue(queue_name);
                ch.sendToQueue(queue_name, Buffer.from(JSON.stringify(rating_update)));
            }
            
    }, 10000)
}



require('amqplib/callback_api')
  .connect('amqps://yourid:your_pass@beaver.rmq.cloudamqp.com/yourid', function(err, conn) {
    if (err != null) bail(err);
    console.log("Connected") 
    publisher(conn)
  });